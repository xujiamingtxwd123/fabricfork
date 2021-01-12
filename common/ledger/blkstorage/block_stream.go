package blkstorage

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

var ErrUnexpectedEndOfBlockfile = errors.New("unexpected end of blockfile")

//解析block file 的Steam信息
type blockfileStream struct {
	fileNum       int
	file          *os.File
	reader        *bufio.Reader
	currentOffset int64
}

//在解析block file的时候需要构建该对象进行处理
func newBlockfileStream(rootDir string, fileNum int, startOffset int64) (*blockfileStream, error) {
	var file *os.File
	var err error
	//找到fileName 文件
	filePath := deriveBlockfilePath(rootDir, fileNum)
	if file, err = os.OpenFile(filePath, os.O_RDONLY, 0600); err != nil {
		return nil, errors.Wrapf(err, "error opening block file %s", filePath)
	}
	var newPosition int64
	// whence 表示距离文件开始的offset
	if newPosition, err = file.Seek(startOffset, 0); err != nil {
		return nil, errors.Wrapf(err, "error seeking block file [%s] to startOffset [%d]", filePath, startOffset)
	}
	if newPosition != startOffset {
		panic(fmt.Sprintf("Could not seek block file [%s] to startOffset [%d]. New position = [%d]",
			filePath, startOffset, newPosition))
	}
	s := &blockfileStream{fileNum, file, bufio.NewReader(file), startOffset}
	return s, nil
}

//跳过当前block
func (s *blockfileStream) nextBlockBytes() ([]byte, error) {
	blockBytes, _, err := s.nextBlockBytesAndPlacementInfo()
	return blockBytes, err
}

type blockPlacementInfo struct {
	fileNum          int
	blockStartOffset int64
	blockBytesOffset int64
}

func (s *blockfileStream) nextBlockBytesAndPlacementInfo() ([]byte, *blockPlacementInfo, error) {
	var lenBytes []byte
	var err error
	var fileInfo os.FileInfo
	moreContentAvailable := true

	if fileInfo, err = s.file.Stat(); err != nil {
		return nil, nil, errors.Wrapf(err, "error getting block file stat")
	}

	//已经到文件结尾
	if s.currentOffset == fileInfo.Size() {
		return nil, nil, nil
	}

	//剩余字节数
	remainingBytes := fileInfo.Size() - s.currentOffset

	peekBytes := 8
	if remainingBytes < int64(peekBytes) {
		peekBytes = int(remainingBytes)
		moreContentAvailable = false
	}

	//读取存储头
	if lenBytes, err = s.reader.Peek(peekBytes); err != nil {
		return nil, nil, errors.Wrapf(err, "error peeking [%d] bytes from block file", peekBytes)
	}

	//n 是头长度  length 体长度
	length, n := proto.DecodeVarint(lenBytes)
	if n == 0 {
		// proto.DecodeVarint did not consume any byte at all which means that the bytes
		// representing the size of the block are partial bytes
		if !moreContentAvailable {
			return nil, nil, ErrUnexpectedEndOfBlockfile
		}
		panic(errors.Errorf("Error in decoding varint bytes [%#v]", lenBytes))
	}
	//获取总长度
	bytesExpected := int64(n) + int64(length)
	if bytesExpected > remainingBytes {
		return nil, nil, ErrUnexpectedEndOfBlockfile
	}
	//跳过头长度
	if _, err = s.reader.Discard(n); err != nil {
		return nil, nil, errors.Wrapf(err, "error discarding [%d] bytes", n)
	}
	//读取体长度
	blockBytes := make([]byte, length)
	if _, err = io.ReadAtLeast(s.reader, blockBytes, int(length)); err != nil {
		return nil, nil, errors.Wrapf(err, "error reading [%d] bytes from file number [%d]", length, s.fileNum)
	}
	//获取当前区块信息
	blockPlacementInfo := &blockPlacementInfo{
		fileNum:          s.fileNum,
		blockStartOffset: s.currentOffset,
		blockBytesOffset: s.currentOffset + int64(n)}
	//跳过当前区块
	s.currentOffset += int64(n) + int64(length)
	return blockBytes, blockPlacementInfo, nil
}

func (s *blockfileStream) close() error {
	return errors.WithStack(s.file.Close())
}

//数据结构是block file stream的高层封装，带有 file num的范围
type blockStream struct {
	rootDir           string
	currentFileNum    int
	endFileNum        int
	currentFileStream *blockfileStream
}

func newBlockStream(rootDir string, startFileNum int, startOffset int64, endFileNum int) (*blockStream, error) {
	startFileStream, err := newBlockfileStream(rootDir, startFileNum, startOffset)
	if err != nil {
		return nil, err
	}
	return &blockStream{rootDir, startFileNum, endFileNum, startFileStream}, nil
}

//如果某block file num 扫描完成会继续move
func (s *blockStream) nextBlockBytesAndPlacementInfo() ([]byte, *blockPlacementInfo, error) {
	var blockBytes []byte
	var blockPlacementInfo *blockPlacementInfo
	var err error
	if blockBytes, blockPlacementInfo, err = s.currentFileStream.nextBlockBytesAndPlacementInfo(); err != nil {
		logger.Errorf("Error reading next block bytes from file number [%d]: %s", s.currentFileNum, err)
		return nil, nil, err
	}
	logger.Debugf("blockbytes [%d] read from file [%d]", len(blockBytes), s.currentFileNum)
	if blockBytes == nil && (s.currentFileNum < s.endFileNum || s.endFileNum < 0) {
		logger.Debugf("current file [%d] exhausted. Moving to next file", s.currentFileNum)
		if err = s.moveToNextBlockfileStream(); err != nil {
			return nil, nil, err
		}
		return s.nextBlockBytesAndPlacementInfo()
	}
	return blockBytes, blockPlacementInfo, nil
}

func (s *blockStream) moveToNextBlockfileStream() error {
	var err error
	if err = s.currentFileStream.close(); err != nil {
		return err
	}
	s.currentFileNum++
	if s.currentFileStream, err = newBlockfileStream(s.rootDir, s.currentFileNum, 0); err != nil {
		return err
	}
	return nil
}

func (s *blockStream) nextBlockBytes() ([]byte, error) {
	blockBytes, _, err := s.nextBlockBytesAndPlacementInfo()
	return blockBytes, err
}
