package tpm2net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

type Handler interface {
	HandlePacket(packet *Packet)
}

type Server struct {
	MaxPacketNum  int
	MaxPacketSize int
}

type Header struct {
	Start       uint8
	Type        uint8
	PayloadSize uint16
	PktNum      uint8
	PktTotal    uint8
}

type Packet struct {
	Header Header
	Data   []uint8
}

const (
	TPM2NetStart   = 0x9c
	TPM2NetData    = 0xda
	TPM2NetCommand = 0xc0
	TPM2NetRequest = 0xaa
	TPM2NetEnd     = 0x36

	RcvBufSize = 65535
)

var ErrFormat = errors.New("Incorrect packet")

func (pkt *Packet) Parse(rd io.Reader) error {
	if err := binary.Read(rd, binary.BigEndian, &pkt.Header); err != nil {
		return err
	}

	if pkt.Header.Start != TPM2NetStart || pkt.Header.Type != TPM2NetData {
		return ErrFormat
	}

	sz := int(pkt.Header.PayloadSize)
	if cap(pkt.Data) >= sz {
		pkt.Data = pkt.Data[:sz]
	} else {
		pkt.Data = make([]uint8, sz)
	}

	if _, err := io.ReadFull(rd, pkt.Data); err != nil {
		return err
	}

	var end uint8
	if err := binary.Read(rd, binary.BigEndian, &end); err != nil {
		return err
	}

	if end != TPM2NetEnd {
		return ErrFormat
	}

	return nil
}

func (srv *Server) Serve(conn net.PacketConn, handler Handler) error {
	buf := make([]byte, RcvBufSize)
	var pkt Packet

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}

		err = pkt.Parse(bytes.NewReader(buf[:n]))

		if err != nil {
			log.Println(err)
		} else if int(pkt.Header.PktNum) > srv.MaxPacketNum {
			log.Println(ErrFormat)
		} else if len(pkt.Data) > srv.MaxPacketSize {
			log.Println(ErrFormat)
		} else {
			handler.HandlePacket(&pkt)
		}
	}
}
