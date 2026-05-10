package export

import "net"

// Exporter sends UDP datagrams to a collector address.
type Exporter struct {
	conn *net.UDPConn
}

func New(addr string) (*Exporter, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &Exporter{conn: conn}, nil
}

func (e *Exporter) Send(data []byte) error {
	_, err := e.conn.Write(data)
	return err
}

func (e *Exporter) Close() { e.conn.Close() }
