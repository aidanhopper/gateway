package gateway

type MinecraftInfo struct{}

func (c *tcpConn) GetMinecraftInfo() (*MinecraftInfo, error) {
	return nil, nil
}
