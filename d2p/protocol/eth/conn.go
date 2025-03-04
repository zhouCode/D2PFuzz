package eth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/AgnopraxLab/D2PFuzz/d2p/protocol/snap"
)

var (
	pretty = spew.ConfigState{
		Indent:                  "  ",
		DisableCapacities:       true,
		DisablePointerAddresses: true,
		SortKeys:                true,
	}
	timeout = 2 * time.Second
)

func (s *Suite) dial() (*Conn, error) {
	pri, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	return s.dialAs(pri)
}

func (s *Suite) Dial() (*Conn, error) {
	return s.dialAs(s.pri)
}

func (s *Suite) dialAs(key *ecdsa.PrivateKey) (*Conn, error) {
	// Validate basic parameters
	if s.DestList == nil {
		return nil, fmt.Errorf("error: target node information is empty")
	}
	if s.DestList.IP() == nil {
		return nil, fmt.Errorf("error: invalid target IP address")
	}
	if key == nil {
		return nil, fmt.Errorf("error: private key not set")
	}

	// Build target address
	targetAddr := fmt.Sprintf("%v:%d", s.DestList.IP(), s.DestList.TCP())

	// Attempt TCP connection
	fd, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// Provide detailed error diagnostic information
		return nil, fmt.Errorf("TCP connection failed (target=%s): %v\nPossible reasons:\n"+
			"1. Target node is not running\n"+
			"2. Port is not open\n"+
			"3. Network connectivity issues\n"+
			"4. Firewall restrictions", targetAddr, err)
	}

	// Create RLPx connection with the established TCP connection
	conn := Conn{Conn: rlpx.NewConn(fd, s.DestList.Pubkey())}
	conn.ourKey = key

	// Perform encryption handshake
	_, err = conn.Handshake(conn.ourKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("encryption handshake failed: %v", err)
	}

	// Set protocol versions and capabilities
	conn.caps = []p2p.Cap{
		{Name: "eth", Version: 67},
		{Name: "eth", Version: 68},
	}
	conn.ourHighestProtoVersion = 68

	return &conn, nil
}

// dialSnap creates a connection with snap/1 capability.
func (s *Suite) dialSnap() (*Conn, error) {
	conn, err := s.dial()
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	conn.caps = append(conn.caps, p2p.Cap{Name: "snap", Version: 1})
	conn.ourHighestSnapProtoVersion = 1
	return conn, nil
}

type Conn struct {
	*rlpx.Conn
	ourKey                     *ecdsa.PrivateKey
	negotiatedProtoVersion     uint
	negotiatedSnapProtoVersion uint
	ourHighestProtoVersion     uint
	ourHighestSnapProtoVersion uint
	caps                       []p2p.Cap
}

func (c *Conn) Read() (uint64, []byte, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	code, data, _, err := c.Conn.Read()
	if err != nil {
		return 0, nil, err
	}
	return code, data, nil
}

// ReadMsg attempts to read a devp2p message with a specific code.
func (c *Conn) ReadMsg(proto Proto, code uint64, msg any) error {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		got, data, err := c.Read()
		if err != nil {
			return err
		}
		if protoOffset(proto)+code == got {
			return rlp.DecodeBytes(data, msg)
		}
	}
}

func (s *Suite) ReadMsg(proto Proto, code uint64, msg interface{}) error {
	if s.conn == nil {
		return errors.New("connection not established")
	}

	s.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		got, data, err := s.conn.Read()
		if err != nil {
			return err
		}
		if protoOffset(proto)+code == got {
			return rlp.DecodeBytes(data, msg)
		}
	}
}

// Original Write
func (c *Conn) Write(proto Proto, code uint64, msg any) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	payload, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(protoOffset(proto)+code, payload)
	return err
}

// func (s *Suite) SendMsg(proto Proto, code uint64, msg interface{}) error {

// 	if !s.IsConnected() {
// 		fmt.Println(">>> 错误: 连接未建立")
// 		return errors.New("connection not established")
// 	}

// 	err := s.conn.Write(proto, code, msg)
// 	if err != nil {
// 		fmt.Printf(">>> Write failed: %v\n", err)
// 		return err
// 	}

// 	return nil
// }

// TODO: Mutate sendMsg for fuzzing
func (s *Suite) SendMsg(proto Proto, code uint64, msg interface{}) error {

	if !s.IsConnected() {
		fmt.Println(">>> 错误: 连接未建立")
		return errors.New("connection not established")
	}

	// 只对非 Status 消息进行变异
	// if code != StatusMsg {
	// 	// 变异协议类型 (在 baseProto, ethProto, snapProto 中选择)
	// 	if fuzzing.RandBool() {
	// 		protos := []Proto{baseProto, ethProto, snapProto}
	// 		proto = protos[fuzzing.RandIntRange(0, len(protos)-1)]
	// 	}

	// 	// 变异消息码 (在有效的消息码范围内选择)
	// 	if fuzzing.RandBool() {
	// 		// eth 协议的有效消息码范围是 0x00-0x10
	// 		code = uint64(fuzzing.RandIntRange(0, 0x10))
	// 	}
	// }

	err := s.conn.Write(proto, code, msg)
	if err != nil {
		fmt.Printf(">>> Write failed: %v\n", err)
		return err
	}

	return nil
}

func (s *Suite) SnapRequest(code uint64, msg any) (any, error) {
	if err := s.conn.Write(snapProto, code, msg); err != nil {
		return nil, fmt.Errorf("could not write to connection: %v", err)
	}
	return s.conn.ReadSnap()
}

// peer performs both the protocol handshake and the status message
// exchange with the node to peer with it.
func (c *Conn) peer(chain *Chain, status *StatusPacket) error {
	if err := c.handshake(); err != nil {
		return fmt.Errorf("handshake failed: %v", err)
	}
	if err := c.statusExchange(chain, status); err != nil {
		return fmt.Errorf("status exchange failed: %v", err)
	}
	return nil
}

func (c *Conn) Peer(chain *Chain, status *StatusPacket) error {
	fmt.Println(">>> 开始握手")
	if err := c.handshake(); err != nil {
		fmt.Printf(">>> 握手失败: %v\n", err)
		return fmt.Errorf("handshake failed: %v", err)
	}
	fmt.Println(">>> 握手成功，开始状态交换")
	if err := c.statusExchange(chain, status); err != nil {
		fmt.Printf(">>> 状态交换失败: %v\n", err)
		return fmt.Errorf("status exchange failed: %v", err)
	}
	fmt.Println(">>> 状态交换成功")
	return nil
}

// handshake performs a protocol handshake with the node.
func (c *Conn) handshake() error {
	fmt.Println(">>> 开始写入握手消息")
	// Write hello to a client.
	pub0 := crypto.FromECDSAPub(&c.ourKey.PublicKey)[1:]
	ourHandshake := &protoHandshake{
		Version: 5,
		Caps:    c.caps,
		ID:      pub0,
	}
	if err := c.Write(baseProto, handshakeMsg, ourHandshake); err != nil {
		fmt.Printf(">>> 写入握手消息失败: %v\n", err)
		return fmt.Errorf("write to connection failed: %v", err)
	}
	fmt.Println(">>> 写入握手消息成功，开始读取握手消息")
	// Read hello from a client.
	code, data, err := c.Read()
	if err != nil {
		fmt.Printf(">>> 读取握手消息失败: %v\n", err)
		return fmt.Errorf("erroring reading handshake: %v", err)
	}
	switch code {
	case handshakeMsg:
		fmt.Println(">>> 收到握手消息，开始解码")
		msg := new(protoHandshake)
		if err := rlp.DecodeBytes(data, &msg); err != nil {
			fmt.Printf(">>> 解码握手消息失败: %v\n", err)
			return fmt.Errorf("error decoding handshake msg: %v", err)
		}
		fmt.Println(">>> 解码握手消息成功")
		// Set snappy if a version is at least 5.
		if msg.Version >= 5 {
			c.SetSnappy(true)
		}
		c.negotiateEthProtocol(msg.Caps)
		if c.negotiatedProtoVersion == 0 {
			fmt.Println(">>> 协议协商失败")
			return fmt.Errorf("could not negotiate eth protocol (remote caps: %v, local eth version: %v)", msg.Caps, c.ourHighestProtoVersion)
		}
		// If we require a snap, verify that it was negotiated.
		if c.ourHighestSnapProtoVersion != c.negotiatedSnapProtoVersion {
			fmt.Println(">>> Snap 协议协商失败")
			return fmt.Errorf("could not negotiate snap protocol (remote caps: %v, local snap version: %v)", msg.Caps, c.ourHighestSnapProtoVersion)
		}
		fmt.Println(">>> 握手成功")
		return nil
	default:
		fmt.Printf(">>> 错误的握手消息代码: %d\n", code)
		return fmt.Errorf("bad handshake: got msg code %d", code)
	}
}

// negotiateEthProtocol sets the Conn's eth protocol version to highest
// advertised capability from peer.
func (c *Conn) negotiateEthProtocol(caps []p2p.Cap) {
	var highestEthVersion uint
	var highestSnapVersion uint
	for _, capability := range caps {
		switch capability.Name {
		case "eth":
			if capability.Version > highestEthVersion && capability.Version <= c.ourHighestProtoVersion {
				highestEthVersion = capability.Version
			}
		case "snap":
			if capability.Version > highestSnapVersion && capability.Version <= c.ourHighestSnapProtoVersion {
				highestSnapVersion = capability.Version
			}
		}
	}
	c.negotiatedProtoVersion = highestEthVersion
	c.negotiatedSnapProtoVersion = highestSnapVersion
}

// statusExchange performs a `Status` message exchange with the given node.
func (c *Conn) statusExchange(chain *Chain, status *StatusPacket) error {
	fmt.Println(">>> 开始状态交换")
	var receivedStatus *StatusPacket

loop:
	for {
		code, data, err := c.Read()
		if err != nil {
			fmt.Printf(">>> 从连接读取失败: %v\n", err)
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch code {
		case StatusMsg + protoOffset(ethProto):
			fmt.Println(">>> 收到状态消息，开始解码")
			msg := new(StatusPacket)
			if err := rlp.DecodeBytes(data, &msg); err != nil {
				fmt.Printf(">>> 解码状态包失败: %v\n", err)
				return fmt.Errorf("error decoding status packet: %w", err)
			}
			fmt.Println(">>> 解码状态包成功")
			receivedStatus = msg // 记录收到的状态信息

			if have, want := msg.Head, chain.blocks[chain.Len()-1].Hash(); have != want {
				fmt.Printf(">>> 错误的头块: 期望 %#x (块 %d) 实际 %#x\n", want, chain.blocks[chain.Len()-1].NumberU64(), have)
				// 记录实际收到的头块哈希
			}
			if have, want := msg.TD.Cmp(chain.TD()), 0; have != want {
				fmt.Printf(">>> 错误的TD: 期望 %v 实际 %v\n", want, have)
				// 记录实际收到的总难度
			}
			if have, want := msg.ForkID, chain.ForkID(); !reflect.DeepEqual(have, want) {
				fmt.Printf(">>> 错误的Fork ID: 期望 %v 实际 %v\n", want, have)
				// 记录实际收到的Fork ID
			}
			if have, want := msg.ProtocolVersion, c.ourHighestProtoVersion; have != uint32(want) {
				fmt.Printf(">>> 错误的协议版本: 期望 %v 实际 %v\n", want, have)
				// 记录实际收到的协议版本
			}
			fmt.Println(">>> 状态消息验证成功")
			break loop
		case discMsg:
			var msg []p2p.DiscReason
			if rlp.DecodeBytes(data, &msg); len(msg) == 0 {
				fmt.Println(">>> 无效的断开连接消息")
				return errors.New("invalid disconnect message")
			}
			fmt.Printf(">>> 收到断开连接消息: %v\n", pretty.Sdump(msg))
			return fmt.Errorf("disconnect received: %v", pretty.Sdump(msg))
		case pingMsg:
			fmt.Println(">>> 收到PING消息，发送PONG响应")
			c.Write(baseProto, pongMsg, nil)
		default:
			fmt.Printf(">>> 错误的状态消息代码: %d\n", code)
			return fmt.Errorf("bad status message: code %d", code)
		}
	}

	fmt.Println(">>> 状态交换成功，准备发送状态消息")
	if c.negotiatedProtoVersion == 0 {
		fmt.Println(">>> 未设置以太坊协议版本")
		return errors.New("eth protocol version must be set in Conn")
	}

	// 使用接收到的状态信息构造状态包
	if status == nil {
		status = &StatusPacket{
			ProtocolVersion: receivedStatus.ProtocolVersion,
			NetworkID:       chain.config.ChainID.Uint64(),
			TD:              receivedStatus.TD,
			Head:            receivedStatus.Head,
			Genesis:         chain.blocks[0].Hash(),
			ForkID:          receivedStatus.ForkID,
		}
	}

	if err := c.Write(ethProto, StatusMsg, status); err != nil {
		fmt.Printf(">>> 写入状态消息失败: %v\n", err)
		return fmt.Errorf("write to connection failed: %v", err)
	}
	fmt.Println(">>> 状态消息发送成功")
	return nil
}

// ReadSnap reads a snap/1 response with the given id from the connection.
func (c *Conn) ReadSnap() (any, error) {
	c.SetReadDeadline(time.Now().Add(timeout))
	for {
		code, data, _, err := c.Conn.Read()
		if err != nil {
			return nil, err
		}
		if getProto(code) != snapProto {
			// Read until snap message.
			continue
		}
		code -= baseProtoLen + ethProtoLen

		var msg any
		switch int(code) {
		case snap.GetAccountRangeMsg:
			msg = new(snap.GetAccountRangePacket)
		case snap.AccountRangeMsg:
			msg = new(snap.AccountRangePacket)
		case snap.GetStorageRangesMsg:
			msg = new(snap.GetStorageRangesPacket)
		case snap.StorageRangesMsg:
			msg = new(snap.StorageRangesPacket)
		case snap.GetByteCodesMsg:
			msg = new(snap.GetByteCodesPacket)
		case snap.ByteCodesMsg:
			msg = new(snap.ByteCodesPacket)
		case snap.GetTrieNodesMsg:
			msg = new(snap.GetTrieNodesPacket)
		case snap.TrieNodesMsg:
			msg = new(snap.TrieNodesPacket)
		default:
			panic(fmt.Errorf("unhandled snap code: %d", code))
		}
		if err := rlp.DecodeBytes(data, msg); err != nil {
			return nil, fmt.Errorf("could not rlp decode message: %v", err)
		}
		return msg, nil
	}
}
