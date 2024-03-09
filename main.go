package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Opcode uint8

const (
	QUERY  Opcode = 0
	IQUERY Opcode = 1
	STATUS Opcode = 2
)

type Rcode uint8

const (
	NOERROR   Rcode = 0
	FORMERR   Rcode = 1
	SERVFAIL  Rcode = 2
	NXDOMAIN  Rcode = 3
	NOTIMP    Rcode = 4
	REFUSED   Rcode = 5
	YXDOMAIN  Rcode = 6
	YXRRSET   Rcode = 7
	NXRRSET   Rcode = 8
	NOTAUTH   Rcode = 9
	NOTZONE   Rcode = 10
	DSOTYPENI Rcode = 11
	BADVERS   Rcode = 16
	BADSIG    Rcode = 16
	BADKEY    Rcode = 17
	BADTIME   Rcode = 18
	BADMODE   Rcode = 19
	BADNAME   Rcode = 20
	BADALG    Rcode = 21
	BADTRUNC  Rcode = 22
	BADCOOKIE Rcode = 23
)

type DNSMessage struct {
	ID     uint16
	QR     bool // false -> query, true -> reply
	OPCODE Opcode
	AA     bool // Authoritative Answer
	TC     bool // TrunCated
	RD     bool // Recursion Desired
	RA     bool // Recursion Available
	RCODE  Rcode
	// QDCOUNT   uint16
	// ANCOUNT   uint16
	// NSCOUNT   uint16
	// ARCOUNT   uint16
	QUESTIONS []DNSQuestion
	ANSWERS   []DNSAnswer
	// AUTHORITY
	// ADDITIONAL
}

type RRType uint16

// There are *far* from all possibilities
const (
	RRA     RRType = 1
	RRAAAA  RRType = 28
	RRCNAME RRType = 5
	RRDNAME RRType = 39
	RRHTTPS RRType = 65
	RRMX    RRType = 15
	RRNS    RRType = 2
	RRPTR   RRType = 12
	RRTXT   RRType = 16
)

type DNSQuestion struct {
	NAME  string
	TYPE  RRType
	CLASS uint16 // 1 for IN (internet), anything else would be weird
}

type DNSAnswer struct {
	NAME  string
	TYPE  RRType
	CLASS uint16 // 1 for IN (internet), anything else would be weird
	TTL   uint32
	// RDLENGTH uint16  // Size of RDATA
	RDATA []byte
}

func (m *DNSMessage) ComposeMsg() []byte {
	header := m.ComposeHeader()
	buf := bytes.NewBuffer(header)
	m.ComposeQuestions(buf)
	m.ComposeAnswers(buf)
	return buf.Bytes()
}

func (m *DNSMessage) ComposeQuestions(buf *bytes.Buffer) {
	for _, q := range m.QUESTIONS {
		parts := strings.Split(q.NAME, ".")
		for _, part := range parts {
			buf.WriteByte(byte(len(part)))
			buf.WriteString(part)
		}
		buf.Write([]byte{
			0,
			byte(q.TYPE >> 8),
			byte(q.TYPE),
			byte(q.CLASS >> 8),
			byte(q.CLASS),
		})
	}
}

func (m *DNSMessage) ComposeAnswers(buf *bytes.Buffer) {
	for _, a := range m.ANSWERS {
		parts := strings.Split(a.NAME, ".")
		for _, part := range parts {
			buf.WriteByte(byte(len(part)))
			buf.WriteString(part)
		}
		rdlength := uint16(len(a.RDATA))
		buf.Write([]byte{
			0,
			byte(a.TYPE >> 8),
			byte(a.TYPE),
			byte(a.CLASS >> 8),
			byte(a.CLASS),
			byte(a.TTL >> 24),
			byte(a.TTL >> 16),
			byte(a.TTL >> 8),
			byte(a.TTL),
			byte(rdlength >> 8),
			byte(rdlength),
		})
		buf.Write(a.RDATA)
	}
}

func (m *DNSMessage) ComposeHeader() []byte {
	var thirdByte byte = 0
	if m.QR {
		thirdByte = 1 << 7
	}
	thirdByte |= (byte(m.OPCODE) & 15) << 3 // bits 2, 3, 4 and 5
	if m.AA {
		thirdByte |= 1 << 2 // 6th bit
	}
	if m.TC {
		thirdByte |= 1 << 1 // 7th bit
	}
	if m.RD {
		thirdByte |= 1
	}

	var fourthByte byte = 0
	if m.RA {
		fourthByte = 1 << 7
	}
	// bits 2, 3 and 4 are zeroed, reserved for future use
	fourthByte |= (byte(m.RCODE) & 15)
	questionCount := uint16(len(m.QUESTIONS))
	answerCount := uint16(len(m.ANSWERS))

	return []byte{
		byte(m.ID >> 8),
		byte(m.ID),
		thirdByte,
		fourthByte,
		byte(questionCount >> 8),
		byte(questionCount),
		byte(answerCount >> 8),
		byte(answerCount),
		0,
		0,
		0,
		0,
		// byte(m.QDCOUNT >> 8),
		// byte(m.QDCOUNT),
		// byte(m.ANCOUNT >> 8),
		// byte(m.ANCOUNT),
		// byte(m.NSCOUNT >> 8),
		// byte(m.NSCOUNT),
		// byte(m.ARCOUNT >> 8),
		// byte(m.ARCOUNT),
	}
}

func parseMsg(buf []byte) (DNSMessage, error) {
	reader := bytes.NewReader(buf)

	msg, err := parseHeader(reader)
	if err != nil {
		return msg, nil
	}

	var qdcount uint16
	binary.Read(reader, binary.BigEndian, &qdcount)
	var ancount uint16
	binary.Read(reader, binary.BigEndian, &ancount)
	var nscount uint16
	binary.Read(reader, binary.BigEndian, &nscount)
	var arcount uint16
	binary.Read(reader, binary.BigEndian, &arcount)

	msg.QUESTIONS, err = parseQuestions(reader, int(qdcount))
	if err != nil {
		return msg, err
	}
	// msg.ANSWERS = parseAnswers(reader, int(ancount))
	// msg.ANSWERS = parseAnswers(reader, int(nscount))
	// msg.ANSWERS = parseAnswers(reader, int(arcount))

	return msg, nil
}

func parseQuestions(reader *bytes.Reader, qcount int) ([]DNSQuestion, error) {
	res := make([]DNSQuestion, qcount)
	for i := 0; i < qcount; i++ {
		var sb strings.Builder
		labelCount := 0
		for {
			labelLength, err := reader.ReadByte()
			if labelLength == 0 {
				break // end of labels
			}
			if labelCount != 0 {
				sb.WriteRune('.')
			}

			if (labelLength >> 6) == 3 {
				// pointer
				offset1 := labelLength & 63
				offset2, _ := reader.ReadByte()
				offset := uint(offset1)<<8 | uint(offset2)

				buf := make([]byte, 1)
				reader.ReadAt(buf, int64(offset))
				label := make([]byte, buf[0])
				reader.ReadAt(label, int64(offset)+1)
				sb.Write(label)
				break // pointers also terminate the label sequence
			}
			// normal label
			label := make([]byte, labelLength)
			_, err = reader.Read(label)
			if err != nil {
				return res, err
			}
			sb.Write(label)
			labelCount++
		}
		var rrtype uint16
		binary.Read(reader, binary.BigEndian, &rrtype)
		var class uint16
		binary.Read(reader, binary.BigEndian, &class)

		res[i] = DNSQuestion{
			NAME:  sb.String(),
			TYPE:  RRType(rrtype),
			CLASS: class,
		}
	}
	return res, nil
}

// Reads 4 bytes from reader, always. Returns an EOF if the buffer is too small.
func parseHeader(r *bytes.Reader) (DNSMessage, error) {
	msg := DNSMessage{}
	binary.Read(r, binary.BigEndian, &msg.ID)

	thirdByte, err := r.ReadByte()
	if err != nil {
		return msg, fmt.Errorf("Error reading DNS header: %w", err)
	}
	if (thirdByte >> 7) == 1 {
		msg.QR = true
	}
	msg.OPCODE = Opcode((thirdByte >> 3) & 15) // bits 2, 3, 4, and 5
	if (thirdByte & 4) == 1 {
		msg.AA = true
	}
	if (thirdByte & 2) == 1 {
		msg.TC = true
	}
	if (thirdByte & 1) == 1 {
		msg.RD = true
	}

	fourthByte, err := r.ReadByte()
	if err != nil {
		return msg, fmt.Errorf("Error reading DNS header: %w", err)
	}
	if (fourthByte >> 7) == 1 {
		msg.RA = true
	}
	// bit 2, 3, and 4 are zeroed and reserved for future use
	msg.RCODE = Rcode(fourthByte & 15)

	return msg, nil
}

func main() {
	fmt.Println(os.Args)
	if len(os.Args) > 1 && os.Args[1] == "--resolver" {
		resolverAddress := os.Args[2]
		doResolver(resolverAddress)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)
	for {
		_, source, err := udpConn.ReadFromUDP(buf) // first one is size
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		msg, err := parseMsg(buf)
		if err != nil {
			fmt.Println("Error parsing message:", err)
			break
		}

		// nothing about this part of the assignment makes any sense; there's a reason DNS servers don't handle requests with multiple questions
		// if len(os.Args) > 1 && os.Args[1] == "--resolver" {
		// 	resolverAddress := os.Args[2]
		// 	udpAddr, err = net.ResolveUDPAddr("udp", resolverAddress)
		// 	if err != nil {
		// 		fmt.Println("Failed to resolve UDP address:", err)
		// 		return
		// 	}
		// 	resolverConn, err := net.DialUDP("udp", nil, udpAddr)
		// 	if err != nil {
		// 		return
		// 	}
		// 	defer resolverConn.Close()

		// 	resolverMsgs := []DNSMessage{}
		// 	for _, q := range msg.QUESTIONS {
		// 		newMsg := msg
		// 		newMsg.QUESTIONS = []DNSQuestion{q}
		// 		buf := newMsg.ComposeMsg()

		// 		// copy onto resolver conn
		// 		_, err = resolverConn.Write(buf)
		// 		if err != nil {
		// 			fmt.Println("Error passing data to resolver:", err)
		// 			return
		// 		}

		// 		// Set timeout for resolver
		// 		deadline := time.Now().Add(time.Second * 5)
		// 		err = resolverConn.SetReadDeadline(deadline)
		// 		if err != nil {
		// 			return
		// 		}

		// 		// Read resolver response
		// 		responseBuf := make([]byte, 512)
		// 		_, _, err = resolverConn.ReadFrom(responseBuf)
		// 		if err != nil {
		// 			fmt.Println("Error while receiving resolver response:", err)
		// 			return
		// 		}
		// 		resolverMsg, _ := parseMsg(responseBuf)
		// 		resolverMsgs = append(resolverMsgs, resolverMsg)
		// 	}
		// 	resolverMsgAnswers := []DNSAnswer{}
		// 	for _, msg := range resolverMsgs {
		// 		resolverMsgAnswers = append(resolverMsgAnswers, msg.ANSWERS...)
		// 	}
		// 	ourResponse := resolverMsgs[0]
		// 	ourResponse.ANSWERS = resolverMsgAnswers
		// 	response := ourResponse.ComposeMsg()
		// 	_, err = udpConn.WriteToUDP(response, source)
		// 	if err != nil {
		// 		fmt.Println("Failed to send response:", err)
		// 	}
		// 	continue
		// }

		resMsg := new(DNSMessage)
		resMsg.ID = msg.ID
		resMsg.QR = true
		resMsg.OPCODE = msg.OPCODE
		resMsg.RD = msg.RD
		if msg.OPCODE == 0 {
			resMsg.RCODE = NOERROR
		} else {
			resMsg.RCODE = NOTIMP
		}
		resMsg.QUESTIONS = msg.QUESTIONS
		resMsg.ANSWERS = []DNSAnswer{}
		for _, q := range msg.QUESTIONS {
			answer := DNSAnswer{
				NAME:  q.NAME,
				TYPE:  q.TYPE,
				CLASS: q.CLASS,
				TTL:   60,
				RDATA: []byte{8, 8, 8, 8},
			}
			resMsg.ANSWERS = append(resMsg.ANSWERS, answer)
		}

		response := resMsg.ComposeMsg()
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func doResolver(resolverName string) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer conn.Close()

	udpAddr, err = net.ResolveUDPAddr("udp", resolverName)
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	resolverConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer resolverConn.Close()

	buf := make([]byte, 512)
	for {
		// read from main conn
		_, source, err := conn.ReadFromUDP(buf) // first one is size
		if err != nil {
			fmt.Println("Error receiving data:", err)
			return
		}
		// copy onto resolver conn
		_, err = resolverConn.Write(buf)
		if err != nil {
			fmt.Println("Error passing data to resolver:", err)
			return
		}

		// Set timeout for resolver
		deadline := time.Now().Add(time.Second * 5)
		err = resolverConn.SetReadDeadline(deadline)
		if err != nil {
			return
		}

		// Read resolver response
		_, _, err = resolverConn.ReadFrom(buf)
		if err != nil {
			fmt.Println("Error while receiving resolver response:", err)
			return
		}

		// Pass resolver response onto main conn
		_, err = conn.WriteToUDP(buf, source)
	}
}
