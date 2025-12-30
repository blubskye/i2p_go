package irc

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server is an IRC server.
type Server struct {
	mu sync.RWMutex

	config   *ServerConfig
	listener net.Listener
	running  bool
	done     chan struct{}

	users    map[string]*User // nick -> user
	channels map[string]*Channel

	// Stats
	startTime   time.Time
	connections int64
}

// NewServer creates a new IRC server.
func NewServer(config *ServerConfig) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}
	return &Server{
		config:    config,
		users:     make(map[string]*User),
		channels:  make(map[string]*Channel),
		done:      make(chan struct{}),
		startTime: time.Now(),
	}
}

// Start starts the IRC server on the given address.
func (s *Server) Start(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go s.acceptLoop()
	go s.pingLoop()

	return nil
}

// StartWithListener starts the server with a custom listener (for I2P).
func (s *Server) StartWithListener(listener net.Listener) error {
	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go s.acceptLoop()
	go s.pingLoop()

	return nil
}

// Stop stops the server.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)

	// Close all connections
	for _, user := range s.users {
		user.conn.Close()
	}
	s.users = make(map[string]*User)
	s.channels = make(map[string]*Channel)

	s.listener.Close()
	s.mu.Unlock()
}

// acceptLoop accepts new connections.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		s.mu.Lock()
		s.connections++
		s.mu.Unlock()

		go s.handleConnection(conn)
	}
}

// handleConnection handles a new connection.
func (s *Server) handleConnection(conn net.Conn) {
	host := conn.RemoteAddr().String()
	// Truncate for I2P destinations
	if len(host) > 52 {
		host = host[:52]
	}

	tc := &tcpConn{conn: conn}
	user := NewUser(tc, host)
	user.Server = s

	defer s.removeUser(user)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		msg := parseMessage(line)
		if msg != nil {
			s.handleMessage(user, msg)
		}
	}
}

// tcpConn wraps a TCP connection.
type tcpConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *tcpConn) Send(msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.conn.Write([]byte(msg + "\r\n"))
	return err
}

func (c *tcpConn) Close() error {
	return c.conn.Close()
}

func (c *tcpConn) RemoteAddr() string {
	return c.conn.RemoteAddr().String()
}

// pingLoop sends periodic pings.
func (s *Server) pingLoop() {
	ticker := time.NewTicker(s.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.RLock()
			users := make([]*User, 0, len(s.users))
			for _, u := range s.users {
				users = append(users, u)
			}
			s.mu.RUnlock()

			for _, user := range users {
				user.mu.Lock()
				if user.pingPending {
					// Timeout
					user.mu.Unlock()
					user.Send("ERROR :Ping timeout")
					user.conn.Close()
				} else {
					user.pingPending = true
					user.lastPing = time.Now()
					user.mu.Unlock()
					user.Send("PING :" + s.config.Name)
				}
			}
		}
	}
}

// handleMessage handles an IRC message.
func (s *Server) handleMessage(user *User, msg *Message) {
	cmd := strings.ToUpper(msg.Command)

	// Commands available before registration
	switch cmd {
	case "NICK":
		s.handleNick(user, msg)
		return
	case "USER":
		s.handleUser(user, msg)
		return
	case "PASS":
		s.handlePass(user, msg)
		return
	case "CAP":
		// Capability negotiation - just acknowledge
		return
	case "QUIT":
		s.handleQuit(user, msg)
		return
	case "PONG":
		user.mu.Lock()
		user.pingPending = false
		user.mu.Unlock()
		return
	}

	// Commands requiring registration
	if !user.IsRegistered() {
		user.SendNumeric(s.config.Name, ERR_NOTREGISTERED, ":You have not registered")
		return
	}

	switch cmd {
	case "PING":
		s.handlePing(user, msg)
	case "JOIN":
		s.handleJoin(user, msg)
	case "PART":
		s.handlePart(user, msg)
	case "PRIVMSG":
		s.handlePrivmsg(user, msg)
	case "NOTICE":
		s.handleNotice(user, msg)
	case "MODE":
		s.handleMode(user, msg)
	case "TOPIC":
		s.handleTopic(user, msg)
	case "NAMES":
		s.handleNames(user, msg)
	case "LIST":
		s.handleList(user, msg)
	case "KICK":
		s.handleKick(user, msg)
	case "INVITE":
		s.handleInvite(user, msg)
	case "WHO":
		s.handleWho(user, msg)
	case "WHOIS":
		s.handleWhois(user, msg)
	case "AWAY":
		s.handleAway(user, msg)
	case "OPER":
		s.handleOper(user, msg)
	case "MOTD":
		s.sendMOTD(user)
	case "LUSERS":
		s.sendLusers(user)
	case "VERSION":
		user.SendNumeric(s.config.Name, "351", "i2p-irc-1.0 "+s.config.Name+" :I2P IRC Server")
	case "TIME":
		user.SendNumeric(s.config.Name, "391", s.config.Name+" :"+time.Now().Format(time.RFC1123))
	default:
		user.SendNumeric(s.config.Name, ERR_UNKNOWNCOMMAND, cmd+" :Unknown command")
	}
}

// handleNick handles the NICK command.
func (s *Server) handleNick(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NONICKNAMEGIVEN, ":No nickname given")
		return
	}

	nick := msg.Params[0]

	// Validate nick
	if !isValidNick(nick, s.config.MaxNickLen) {
		user.SendNumeric(s.config.Name, ERR_ERRONEUSNICKNAME, nick+" :Erroneous nickname")
		return
	}

	s.mu.Lock()
	// Check if nick is in use
	if existing, ok := s.users[strings.ToLower(nick)]; ok && existing != user {
		s.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_NICKNAMEINUSE, nick+" :Nickname is already in use")
		return
	}

	oldNick := user.Nick
	wasRegistered := user.IsRegistered()

	// Update nick
	if oldNick != "" {
		delete(s.users, strings.ToLower(oldNick))
	}
	user.mu.Lock()
	user.Nick = nick
	user.mu.Unlock()
	s.users[strings.ToLower(nick)] = user
	s.mu.Unlock()

	// Notify channels of nick change
	if wasRegistered && oldNick != "" {
		s.broadcastToUserChannels(user, fmt.Sprintf(":%s!%s@%s NICK :%s",
			oldNick, user.Username, user.Host, nick))
	}

	// Check if registration is complete
	s.checkRegistration(user)
}

// handleUser handles the USER command.
func (s *Server) handleUser(user *User, msg *Message) {
	if user.IsRegistered() {
		user.SendNumeric(s.config.Name, ERR_ALREADYREGISTERED, ":You may not reregister")
		return
	}

	if len(msg.Params) < 4 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "USER :Not enough parameters")
		return
	}

	user.mu.Lock()
	user.Username = msg.Params[0]
	user.Realname = msg.Params[3]
	if strings.HasPrefix(user.Realname, ":") {
		user.Realname = user.Realname[1:]
	}
	user.mu.Unlock()

	s.checkRegistration(user)
}

// handlePass handles the PASS command.
func (s *Server) handlePass(user *User, msg *Message) {
	if user.IsRegistered() {
		user.SendNumeric(s.config.Name, ERR_ALREADYREGISTERED, ":You may not reregister")
		return
	}
	// Store password for later verification if needed
}

// checkRegistration checks if registration is complete and sends welcome.
func (s *Server) checkRegistration(user *User) {
	user.mu.RLock()
	nick := user.Nick
	username := user.Username
	registered := user.registered
	user.mu.RUnlock()

	if registered || nick == "" || username == "" {
		return
	}

	user.SetRegistered()

	// Send welcome messages
	user.SendNumeric(s.config.Name, RPL_WELCOME, fmt.Sprintf(":Welcome to the %s IRC Network %s",
		s.config.Network, user.Prefix()))
	user.SendNumeric(s.config.Name, RPL_YOURHOST, fmt.Sprintf(":Your host is %s, running i2p-irc-1.0",
		s.config.Name))
	user.SendNumeric(s.config.Name, RPL_CREATED, fmt.Sprintf(":This server was created %s",
		s.startTime.Format(time.RFC1123)))
	user.SendNumeric(s.config.Name, RPL_MYINFO, fmt.Sprintf("%s i2p-irc-1.0 iowrs biklmnopstv",
		s.config.Name))

	s.sendLusers(user)
	s.sendMOTD(user)
}

// handlePing handles the PING command.
func (s *Server) handlePing(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		return
	}
	user.Send(":" + s.config.Name + " PONG " + s.config.Name + " :" + msg.Params[0])
}

// handleJoin handles the JOIN command.
func (s *Server) handleJoin(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "JOIN :Not enough parameters")
		return
	}

	channels := strings.Split(msg.Params[0], ",")
	keys := []string{}
	if len(msg.Params) > 1 {
		keys = strings.Split(msg.Params[1], ",")
	}

	for i, chanName := range channels {
		chanName = strings.TrimSpace(chanName)
		if !strings.HasPrefix(chanName, "#") && !strings.HasPrefix(chanName, "&") {
			chanName = "#" + chanName
		}

		key := ""
		if i < len(keys) {
			key = keys[i]
		}

		s.joinChannel(user, chanName, key)
	}
}

// joinChannel joins a user to a channel.
func (s *Server) joinChannel(user *User, chanName, key string) {
	chanName = strings.ToLower(chanName)

	s.mu.Lock()
	channel, exists := s.channels[chanName]
	if !exists {
		channel = NewChannel(chanName)
		s.channels[chanName] = channel
	}
	s.mu.Unlock()

	channel.mu.Lock()
	// Check if already in channel
	if _, ok := channel.Users[user.Nick]; ok {
		channel.mu.Unlock()
		return
	}

	// Check modes
	if channel.HasMode('i') && !channel.Invites[user.Nick] {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_INVITEONLYCHAN, chanName+" :Cannot join channel (+i)")
		return
	}

	if channel.Key != "" && channel.Key != key {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_BADCHANNELKEY, chanName+" :Cannot join channel (+k)")
		return
	}

	if channel.Limit > 0 && len(channel.Users) >= channel.Limit {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_CHANNELISFULL, chanName+" :Cannot join channel (+l)")
		return
	}

	if channel.IsBanned(user.Prefix()) {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_BANNEDFROMCHAN, chanName+" :Cannot join channel (+b)")
		return
	}

	// Join the channel
	channel.Users[user.Nick] = user
	if len(channel.Users) == 1 {
		// First user becomes operator
		channel.Operators[user.Nick] = true
	}
	delete(channel.Invites, user.Nick)
	channel.mu.Unlock()

	user.mu.Lock()
	user.Channels[chanName] = channel
	user.mu.Unlock()

	// Send JOIN to all members
	s.broadcastToChannel(channel, fmt.Sprintf(":%s JOIN %s", user.Prefix(), channel.Name))

	// Send topic
	if channel.Topic != "" {
		user.SendNumeric(s.config.Name, RPL_TOPIC, channel.Name+" :"+channel.Topic)
	}

	// Send names list
	s.sendNames(user, channel)
}

// handlePart handles the PART command.
func (s *Server) handlePart(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "PART :Not enough parameters")
		return
	}

	reason := "Leaving"
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	channels := strings.Split(msg.Params[0], ",")
	for _, chanName := range channels {
		s.partChannel(user, strings.TrimSpace(chanName), reason)
	}
}

// partChannel removes a user from a channel.
func (s *Server) partChannel(user *User, chanName, reason string) {
	chanName = strings.ToLower(chanName)

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if !exists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	channel.mu.Lock()
	if _, ok := channel.Users[user.Nick]; !ok {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_NOTONCHANNEL, chanName+" :You're not on that channel")
		return
	}
	channel.mu.Unlock()

	// Send PART to all members
	s.broadcastToChannel(channel, fmt.Sprintf(":%s PART %s :%s", user.Prefix(), channel.Name, reason))

	// Remove user from channel
	channel.mu.Lock()
	delete(channel.Users, user.Nick)
	delete(channel.Operators, user.Nick)
	delete(channel.Voiced, user.Nick)
	isEmpty := len(channel.Users) == 0
	channel.mu.Unlock()

	user.mu.Lock()
	delete(user.Channels, chanName)
	user.mu.Unlock()

	// Remove empty channel
	if isEmpty {
		s.mu.Lock()
		delete(s.channels, chanName)
		s.mu.Unlock()
	}
}

// handlePrivmsg handles the PRIVMSG command.
func (s *Server) handlePrivmsg(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NORECIPIENT, ":No recipient given (PRIVMSG)")
		return
	}
	if len(msg.Params) < 2 {
		user.SendNumeric(s.config.Name, ERR_NOTEXTTOSEND, ":No text to send")
		return
	}

	target := msg.Params[0]
	text := msg.Params[1]

	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		s.sendToChannel(user, target, "PRIVMSG", text)
	} else {
		s.sendToUser(user, target, "PRIVMSG", text)
	}
}

// handleNotice handles the NOTICE command.
func (s *Server) handleNotice(user *User, msg *Message) {
	if len(msg.Params) < 2 {
		return // NOTICE errors are silent
	}

	target := msg.Params[0]
	text := msg.Params[1]

	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		s.sendToChannel(user, target, "NOTICE", text)
	} else {
		s.sendToUser(user, target, "NOTICE", text)
	}
}

// sendToChannel sends a message to a channel.
func (s *Server) sendToChannel(user *User, chanName, msgType, text string) {
	chanName = strings.ToLower(chanName)

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if !exists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	channel.mu.RLock()
	if _, ok := channel.Users[user.Nick]; !ok {
		channel.mu.RUnlock()
		user.SendNumeric(s.config.Name, ERR_CANNOTSENDTOCHAN, chanName+" :Cannot send to channel")
		return
	}

	// Check moderated mode
	if channel.HasMode('m') && !channel.Operators[user.Nick] && !channel.Voiced[user.Nick] {
		channel.mu.RUnlock()
		user.SendNumeric(s.config.Name, ERR_CANNOTSENDTOCHAN, chanName+" :Cannot send to channel (+m)")
		return
	}

	members := make([]*User, 0, len(channel.Users))
	for _, u := range channel.Users {
		if u != user {
			members = append(members, u)
		}
	}
	channel.mu.RUnlock()

	msg := fmt.Sprintf(":%s %s %s :%s", user.Prefix(), msgType, channel.Name, text)
	for _, member := range members {
		member.Send(msg)
	}
}

// sendToUser sends a message to a user.
func (s *Server) sendToUser(from *User, nick, msgType, text string) {
	s.mu.RLock()
	target := s.users[strings.ToLower(nick)]
	s.mu.RUnlock()

	if target == nil {
		from.SendNumeric(s.config.Name, ERR_NOSUCHNICK, nick+" :No such nick/channel")
		return
	}

	target.mu.RLock()
	away := target.Away
	target.mu.RUnlock()

	if away != "" && msgType == "PRIVMSG" {
		from.SendNumeric(s.config.Name, RPL_AWAY, nick+" :"+away)
	}

	target.Send(fmt.Sprintf(":%s %s %s :%s", from.Prefix(), msgType, target.Nick, text))
}

// handleMode handles the MODE command.
func (s *Server) handleMode(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "MODE :Not enough parameters")
		return
	}

	target := msg.Params[0]

	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		s.handleChannelMode(user, target, msg.Params[1:])
	} else {
		s.handleUserMode(user, target, msg.Params[1:])
	}
}

// handleChannelMode handles channel MODE.
func (s *Server) handleChannelMode(user *User, chanName string, params []string) {
	chanName = strings.ToLower(chanName)

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if !exists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	if len(params) == 0 {
		// Return current modes
		channel.mu.RLock()
		modes := "+" + channel.Modes
		channel.mu.RUnlock()
		user.SendNumeric(s.config.Name, RPL_CHANNELMODEIS, channel.Name+" "+modes)
		return
	}

	// Check if user is operator
	if !channel.IsOperator(user.Nick) && !user.IsOperator() {
		user.SendNumeric(s.config.Name, ERR_CHANOPRIVSNEEDED, channel.Name+" :You're not channel operator")
		return
	}

	// Parse and apply mode changes
	modeStr := params[0]
	adding := true
	paramIdx := 1

	for _, c := range modeStr {
		switch c {
		case '+':
			adding = true
		case '-':
			adding = false
		case 'o', 'v':
			if paramIdx < len(params) {
				nick := params[paramIdx]
				paramIdx++
				s.applyChannelUserMode(user, channel, nick, c, adding)
			}
		case 'b':
			if paramIdx < len(params) {
				mask := params[paramIdx]
				paramIdx++
				s.applyBanMode(user, channel, mask, adding)
			} else {
				// List bans
				channel.mu.RLock()
				for _, ban := range channel.Bans {
					user.SendNumeric(s.config.Name, RPL_BANLIST, channel.Name+" "+ban)
				}
				channel.mu.RUnlock()
				user.SendNumeric(s.config.Name, RPL_ENDOFBANLIST, channel.Name+" :End of channel ban list")
			}
		case 'k':
			if adding && paramIdx < len(params) {
				key := params[paramIdx]
				paramIdx++
				channel.mu.Lock()
				channel.Key = key
				if !strings.ContainsRune(channel.Modes, 'k') {
					channel.Modes += "k"
				}
				channel.mu.Unlock()
				s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s +k %s", user.Prefix(), channel.Name, key))
			} else if !adding {
				channel.mu.Lock()
				channel.Key = ""
				channel.Modes = strings.Replace(channel.Modes, "k", "", 1)
				channel.mu.Unlock()
				s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s -k *", user.Prefix(), channel.Name))
			}
		case 'l':
			if adding && paramIdx < len(params) {
				var limit int
				fmt.Sscanf(params[paramIdx], "%d", &limit)
				paramIdx++
				if limit > 0 {
					channel.mu.Lock()
					channel.Limit = limit
					if !strings.ContainsRune(channel.Modes, 'l') {
						channel.Modes += "l"
					}
					channel.mu.Unlock()
					s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s +l %d", user.Prefix(), channel.Name, limit))
				}
			} else if !adding {
				channel.mu.Lock()
				channel.Limit = 0
				channel.Modes = strings.Replace(channel.Modes, "l", "", 1)
				channel.mu.Unlock()
				s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s -l", user.Prefix(), channel.Name))
			}
		case 'i', 'm', 'n', 's', 't', 'p':
			channel.mu.Lock()
			if adding {
				if !strings.ContainsRune(channel.Modes, c) {
					channel.Modes += string(c)
				}
			} else {
				channel.Modes = strings.Replace(channel.Modes, string(c), "", 1)
			}
			channel.mu.Unlock()
			sign := "+"
			if !adding {
				sign = "-"
			}
			s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s %s%c", user.Prefix(), channel.Name, sign, c))
		}
	}
}

// applyChannelUserMode applies +o or +v to a user.
func (s *Server) applyChannelUserMode(user *User, channel *Channel, nick string, mode rune, adding bool) {
	channel.mu.Lock()
	target, ok := channel.Users[nick]
	if !ok {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_USERNOTINCHANNEL, nick+" "+channel.Name+" :They aren't on that channel")
		return
	}

	switch mode {
	case 'o':
		if adding {
			channel.Operators[nick] = true
		} else {
			delete(channel.Operators, nick)
		}
	case 'v':
		if adding {
			channel.Voiced[nick] = true
		} else {
			delete(channel.Voiced, nick)
		}
	}
	channel.mu.Unlock()

	sign := "+"
	if !adding {
		sign = "-"
	}
	s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s %s%c %s", user.Prefix(), channel.Name, sign, mode, target.Nick))
}

// applyBanMode applies +b or -b.
func (s *Server) applyBanMode(user *User, channel *Channel, mask string, adding bool) {
	channel.mu.Lock()
	if adding {
		channel.Bans = append(channel.Bans, mask)
	} else {
		for i, ban := range channel.Bans {
			if ban == mask {
				channel.Bans = append(channel.Bans[:i], channel.Bans[i+1:]...)
				break
			}
		}
	}
	channel.mu.Unlock()

	sign := "+"
	if !adding {
		sign = "-"
	}
	s.broadcastToChannel(channel, fmt.Sprintf(":%s MODE %s %sb %s", user.Prefix(), channel.Name, sign, mask))
}

// handleUserMode handles user MODE.
func (s *Server) handleUserMode(user *User, nick string, params []string) {
	if strings.ToLower(nick) != strings.ToLower(user.Nick) {
		user.SendNumeric(s.config.Name, "502", ":Cannot change mode for other users")
		return
	}

	if len(params) == 0 {
		user.SendNumeric(s.config.Name, "221", "+"+user.Modes)
		return
	}

	modeStr := params[0]
	adding := true
	for _, c := range modeStr {
		switch c {
		case '+':
			adding = true
		case '-':
			adding = false
		case 'i', 'w':
			if adding {
				user.AddMode(c)
			} else {
				user.RemoveMode(c)
			}
		case 'o':
			// Can only remove oper, not add via MODE
			if !adding {
				user.RemoveMode('o')
			}
		}
	}
}

// handleTopic handles the TOPIC command.
func (s *Server) handleTopic(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "TOPIC :Not enough parameters")
		return
	}

	chanName := strings.ToLower(msg.Params[0])

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if !exists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	if len(msg.Params) == 1 {
		// Get topic
		channel.mu.RLock()
		topic := channel.Topic
		channel.mu.RUnlock()

		if topic == "" {
			user.SendNumeric(s.config.Name, RPL_NOTOPIC, channel.Name+" :No topic is set")
		} else {
			user.SendNumeric(s.config.Name, RPL_TOPIC, channel.Name+" :"+topic)
		}
		return
	}

	// Set topic
	if channel.HasMode('t') && !channel.IsOperator(user.Nick) && !user.IsOperator() {
		user.SendNumeric(s.config.Name, ERR_CHANOPRIVSNEEDED, channel.Name+" :You're not channel operator")
		return
	}

	newTopic := msg.Params[1]
	if strings.HasPrefix(newTopic, ":") {
		newTopic = newTopic[1:]
	}

	channel.mu.Lock()
	channel.Topic = newTopic
	channel.TopicBy = user.Nick
	channel.TopicTime = time.Now()
	channel.mu.Unlock()

	s.broadcastToChannel(channel, fmt.Sprintf(":%s TOPIC %s :%s", user.Prefix(), channel.Name, newTopic))
}

// handleNames handles the NAMES command.
func (s *Server) handleNames(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		return
	}

	chanName := strings.ToLower(msg.Params[0])

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if exists {
		s.sendNames(user, channel)
	}
}

// sendNames sends the NAMES list for a channel.
func (s *Server) sendNames(user *User, channel *Channel) {
	channel.mu.RLock()
	names := make([]string, 0, len(channel.Users))
	for nick := range channel.Users {
		prefix := channel.GetPrefix(nick)
		names = append(names, prefix+nick)
	}
	channel.mu.RUnlock()

	sort.Strings(names)

	// Send in chunks of ~400 chars
	chunk := ""
	for _, name := range names {
		if len(chunk)+len(name)+1 > 400 {
			user.SendNumeric(s.config.Name, RPL_NAMREPLY, "= "+channel.Name+" :"+chunk)
			chunk = ""
		}
		if chunk != "" {
			chunk += " "
		}
		chunk += name
	}
	if chunk != "" {
		user.SendNumeric(s.config.Name, RPL_NAMREPLY, "= "+channel.Name+" :"+chunk)
	}

	user.SendNumeric(s.config.Name, RPL_ENDOFNAMES, channel.Name+" :End of /NAMES list")
}

// handleList handles the LIST command.
func (s *Server) handleList(user *User, msg *Message) {
	s.mu.RLock()
	channels := make([]*Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		channels = append(channels, ch)
	}
	s.mu.RUnlock()

	for _, channel := range channels {
		if channel.HasMode('s') || channel.HasMode('p') {
			continue
		}
		channel.mu.RLock()
		user.SendNumeric(s.config.Name, RPL_LIST, fmt.Sprintf("%s %d :%s",
			channel.Name, len(channel.Users), channel.Topic))
		channel.mu.RUnlock()
	}

	user.SendNumeric(s.config.Name, RPL_LISTEND, ":End of /LIST")
}

// handleKick handles the KICK command.
func (s *Server) handleKick(user *User, msg *Message) {
	if len(msg.Params) < 2 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "KICK :Not enough parameters")
		return
	}

	chanName := strings.ToLower(msg.Params[0])
	targetNick := msg.Params[1]
	reason := user.Nick
	if len(msg.Params) > 2 {
		reason = msg.Params[2]
	}

	s.mu.RLock()
	channel, exists := s.channels[chanName]
	s.mu.RUnlock()

	if !exists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	if !channel.IsOperator(user.Nick) && !user.IsOperator() {
		user.SendNumeric(s.config.Name, ERR_CHANOPRIVSNEEDED, channel.Name+" :You're not channel operator")
		return
	}

	channel.mu.Lock()
	target, ok := channel.Users[targetNick]
	if !ok {
		channel.mu.Unlock()
		user.SendNumeric(s.config.Name, ERR_USERNOTINCHANNEL, targetNick+" "+channel.Name+" :They aren't on that channel")
		return
	}
	channel.mu.Unlock()

	// Send KICK to channel
	s.broadcastToChannel(channel, fmt.Sprintf(":%s KICK %s %s :%s", user.Prefix(), channel.Name, target.Nick, reason))

	// Remove target from channel
	channel.mu.Lock()
	delete(channel.Users, target.Nick)
	delete(channel.Operators, target.Nick)
	delete(channel.Voiced, target.Nick)
	channel.mu.Unlock()

	target.mu.Lock()
	delete(target.Channels, chanName)
	target.mu.Unlock()
}

// handleInvite handles the INVITE command.
func (s *Server) handleInvite(user *User, msg *Message) {
	if len(msg.Params) < 2 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "INVITE :Not enough parameters")
		return
	}

	targetNick := msg.Params[0]
	chanName := strings.ToLower(msg.Params[1])

	s.mu.RLock()
	target := s.users[strings.ToLower(targetNick)]
	channel, chanExists := s.channels[chanName]
	s.mu.RUnlock()

	if target == nil {
		user.SendNumeric(s.config.Name, ERR_NOSUCHNICK, targetNick+" :No such nick/channel")
		return
	}

	if !chanExists {
		user.SendNumeric(s.config.Name, ERR_NOSUCHCHANNEL, chanName+" :No such channel")
		return
	}

	if channel.HasMode('i') && !channel.IsOperator(user.Nick) && !user.IsOperator() {
		user.SendNumeric(s.config.Name, ERR_CHANOPRIVSNEEDED, channel.Name+" :You're not channel operator")
		return
	}

	channel.mu.Lock()
	channel.Invites[target.Nick] = true
	channel.mu.Unlock()

	user.SendNumeric(s.config.Name, "341", target.Nick+" "+channel.Name)
	target.Send(fmt.Sprintf(":%s INVITE %s :%s", user.Prefix(), target.Nick, channel.Name))
}

// handleWho handles the WHO command.
func (s *Server) handleWho(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		return
	}

	target := msg.Params[0]

	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		s.mu.RLock()
		channel, exists := s.channels[strings.ToLower(target)]
		s.mu.RUnlock()

		if exists {
			channel.mu.RLock()
			for _, member := range channel.Users {
				flags := "H"
				if channel.Operators[member.Nick] {
					flags += "@"
				} else if channel.Voiced[member.Nick] {
					flags += "+"
				}
				user.SendNumeric(s.config.Name, "352", fmt.Sprintf("%s %s %s %s %s %s :0 %s",
					channel.Name, member.Username, member.Host, s.config.Name, member.Nick, flags, member.Realname))
			}
			channel.mu.RUnlock()
		}
	}

	user.SendNumeric(s.config.Name, "315", target+" :End of /WHO list")
}

// handleWhois handles the WHOIS command.
func (s *Server) handleWhois(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.SendNumeric(s.config.Name, ERR_NONICKNAMEGIVEN, ":No nickname given")
		return
	}

	nick := msg.Params[0]

	s.mu.RLock()
	target := s.users[strings.ToLower(nick)]
	s.mu.RUnlock()

	if target == nil {
		user.SendNumeric(s.config.Name, ERR_NOSUCHNICK, nick+" :No such nick/channel")
		return
	}

	target.mu.RLock()
	user.SendNumeric(s.config.Name, RPL_WHOISUSER, fmt.Sprintf("%s %s %s * :%s",
		target.Nick, target.Username, target.Host, target.Realname))
	user.SendNumeric(s.config.Name, RPL_WHOISSERVER, fmt.Sprintf("%s %s :%s",
		target.Nick, s.config.Name, s.config.Network))

	// Channels
	chans := make([]string, 0)
	for name, ch := range target.Channels {
		prefix := ch.GetPrefix(target.Nick)
		chans = append(chans, prefix+name)
	}
	if len(chans) > 0 {
		user.SendNumeric(s.config.Name, RPL_WHOISCHANNELS, target.Nick+" :"+strings.Join(chans, " "))
	}

	idle := time.Since(target.lastActive).Seconds()
	user.SendNumeric(s.config.Name, RPL_WHOISIDLE, fmt.Sprintf("%s %d %d :seconds idle, signon time",
		target.Nick, int(idle), target.created.Unix()))
	target.mu.RUnlock()

	user.SendNumeric(s.config.Name, RPL_ENDOFWHOIS, target.Nick+" :End of /WHOIS list")
}

// handleAway handles the AWAY command.
func (s *Server) handleAway(user *User, msg *Message) {
	if len(msg.Params) < 1 {
		user.mu.Lock()
		user.Away = ""
		user.mu.Unlock()
		user.SendNumeric(s.config.Name, RPL_UNAWAY, ":You are no longer marked as being away")
	} else {
		user.mu.Lock()
		user.Away = msg.Params[0]
		user.mu.Unlock()
		user.SendNumeric(s.config.Name, RPL_NOWAWAY, ":You have been marked as being away")
	}
}

// handleOper handles the OPER command.
func (s *Server) handleOper(user *User, msg *Message) {
	if len(msg.Params) < 2 {
		user.SendNumeric(s.config.Name, ERR_NEEDMOREPARAMS, "OPER :Not enough parameters")
		return
	}

	name := msg.Params[0]
	password := msg.Params[1]

	if expectedPass, ok := s.config.Operators[name]; ok && expectedPass == password {
		user.AddMode('o')
		user.SendNumeric(s.config.Name, RPL_YOUREOPER, ":You are now an IRC operator")
	} else {
		user.SendNumeric(s.config.Name, ERR_PASSWDMISMATCH, ":Password incorrect")
	}
}

// handleQuit handles the QUIT command.
func (s *Server) handleQuit(user *User, msg *Message) {
	reason := "Quit"
	if len(msg.Params) > 0 {
		reason = msg.Params[0]
	}

	// Notify all channels
	s.broadcastToUserChannels(user, fmt.Sprintf(":%s QUIT :%s", user.Prefix(), reason))

	user.conn.Close()
}

// sendMOTD sends the message of the day.
func (s *Server) sendMOTD(user *User) {
	if len(s.config.MOTD) == 0 {
		user.SendNumeric(s.config.Name, ERR_NOMOTD, ":MOTD File is missing")
		return
	}

	user.SendNumeric(s.config.Name, RPL_MOTDSTART, fmt.Sprintf(":- %s Message of the Day -", s.config.Name))
	for _, line := range s.config.MOTD {
		user.SendNumeric(s.config.Name, RPL_MOTD, ":- "+line)
	}
	user.SendNumeric(s.config.Name, RPL_ENDOFMOTD, ":End of /MOTD command")
}

// sendLusers sends user statistics.
func (s *Server) sendLusers(user *User) {
	s.mu.RLock()
	userCount := len(s.users)
	chanCount := len(s.channels)
	s.mu.RUnlock()

	user.SendNumeric(s.config.Name, RPL_LUSERCLIENT, fmt.Sprintf(":There are %d users on 1 server", userCount))
	user.SendNumeric(s.config.Name, RPL_LUSERCHANNELS, fmt.Sprintf("%d :channels formed", chanCount))
	user.SendNumeric(s.config.Name, RPL_LUSERME, fmt.Sprintf(":I have %d clients and 0 servers", userCount))
}

// removeUser removes a user from the server.
func (s *Server) removeUser(user *User) {
	user.mu.RLock()
	nick := user.Nick
	channels := make([]*Channel, 0, len(user.Channels))
	for _, ch := range user.Channels {
		channels = append(channels, ch)
	}
	user.mu.RUnlock()

	// Remove from all channels
	for _, channel := range channels {
		channel.mu.Lock()
		delete(channel.Users, nick)
		delete(channel.Operators, nick)
		delete(channel.Voiced, nick)
		isEmpty := len(channel.Users) == 0
		channel.mu.Unlock()

		if isEmpty {
			s.mu.Lock()
			delete(s.channels, channel.Name)
			s.mu.Unlock()
		}
	}

	// Remove from server
	s.mu.Lock()
	delete(s.users, strings.ToLower(nick))
	s.mu.Unlock()
}

// broadcastToChannel sends a message to all users in a channel.
func (s *Server) broadcastToChannel(channel *Channel, msg string) {
	channel.mu.RLock()
	users := make([]*User, 0, len(channel.Users))
	for _, u := range channel.Users {
		users = append(users, u)
	}
	channel.mu.RUnlock()

	for _, u := range users {
		u.Send(msg)
	}
}

// broadcastToUserChannels sends a message to all channels a user is in.
func (s *Server) broadcastToUserChannels(user *User, msg string) {
	user.mu.RLock()
	channels := make([]*Channel, 0, len(user.Channels))
	for _, ch := range user.Channels {
		channels = append(channels, ch)
	}
	user.mu.RUnlock()

	sent := make(map[*User]bool)
	sent[user] = true // Don't send to self

	for _, channel := range channels {
		channel.mu.RLock()
		for _, u := range channel.Users {
			if !sent[u] {
				u.Send(msg)
				sent[u] = true
			}
		}
		channel.mu.RUnlock()
	}
}

// parseMessage parses an IRC message.
func parseMessage(line string) *Message {
	if line == "" {
		return nil
	}

	msg := &Message{}
	pos := 0

	// Parse prefix
	if line[0] == ':' {
		idx := strings.Index(line, " ")
		if idx == -1 {
			return nil
		}
		msg.Prefix = line[1:idx]
		pos = idx + 1
	}

	// Parse command and params
	remaining := line[pos:]
	parts := strings.SplitN(remaining, " ", 2)
	msg.Command = parts[0]

	if len(parts) > 1 {
		paramStr := parts[1]
		for paramStr != "" {
			if paramStr[0] == ':' {
				// Trailing parameter
				msg.Params = append(msg.Params, paramStr[1:])
				break
			}
			idx := strings.Index(paramStr, " ")
			if idx == -1 {
				msg.Params = append(msg.Params, paramStr)
				break
			}
			msg.Params = append(msg.Params, paramStr[:idx])
			paramStr = paramStr[idx+1:]
		}
	}

	return msg
}

// isValidNick checks if a nickname is valid.
func isValidNick(nick string, maxLen int) bool {
	if len(nick) == 0 || len(nick) > maxLen {
		return false
	}

	// First char must be letter or special
	first := nick[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
		first == '[' || first == ']' || first == '\\' || first == '`' ||
		first == '_' || first == '^' || first == '{' || first == '|' || first == '}') {
		return false
	}

	// Rest can be alphanumeric, special, or hyphen
	for i := 1; i < len(nick); i++ {
		c := nick[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '[' || c == ']' || c == '\\' || c == '`' ||
			c == '_' || c == '^' || c == '{' || c == '|' || c == '}' || c == '-') {
			return false
		}
	}

	return true
}

// Stats returns server statistics.
func (s *Server) Stats() (users, channels int, uptime time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), len(s.channels), time.Since(s.startTime)
}
