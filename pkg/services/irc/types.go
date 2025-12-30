// Package irc implements an IRC server for I2P.
package irc

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// Server configuration defaults
const (
	DefaultServerName    = "irc.i2p"
	DefaultNetwork       = "I2P-IRC"
	DefaultMOTD          = "Welcome to the I2P IRC Network"
	DefaultMaxNickLen    = 30
	DefaultMaxChannelLen = 50
	DefaultMaxMessageLen = 512
	DefaultMaxChannels   = 20
	DefaultPingInterval  = 120 * time.Second
	DefaultPingTimeout   = 60 * time.Second
)

// IRC numeric replies
const (
	RPL_WELCOME           = "001"
	RPL_YOURHOST          = "002"
	RPL_CREATED           = "003"
	RPL_MYINFO            = "004"
	RPL_ISUPPORT          = "005"
	RPL_LUSERCLIENT       = "251"
	RPL_LUSEROP           = "252"
	RPL_LUSERUNKNOWN      = "253"
	RPL_LUSERCHANNELS     = "254"
	RPL_LUSERME           = "255"
	RPL_AWAY              = "301"
	RPL_UNAWAY            = "305"
	RPL_NOWAWAY           = "306"
	RPL_WHOISUSER         = "311"
	RPL_WHOISSERVER       = "312"
	RPL_WHOISIDLE         = "317"
	RPL_ENDOFWHOIS        = "318"
	RPL_WHOISCHANNELS     = "319"
	RPL_LIST              = "322"
	RPL_LISTEND           = "323"
	RPL_CHANNELMODEIS     = "324"
	RPL_NOTOPIC           = "331"
	RPL_TOPIC             = "332"
	RPL_TOPICWHOTIME      = "333"
	RPL_NAMREPLY          = "353"
	RPL_ENDOFNAMES        = "366"
	RPL_BANLIST           = "367"
	RPL_ENDOFBANLIST      = "368"
	RPL_MOTD              = "372"
	RPL_MOTDSTART         = "375"
	RPL_ENDOFMOTD         = "376"
	RPL_YOUREOPER         = "381"

	ERR_NOSUCHNICK        = "401"
	ERR_NOSUCHCHANNEL     = "403"
	ERR_CANNOTSENDTOCHAN  = "404"
	ERR_TOOMANYCHANNELS   = "405"
	ERR_NORECIPIENT       = "411"
	ERR_NOTEXTTOSEND      = "412"
	ERR_UNKNOWNCOMMAND    = "421"
	ERR_NOMOTD            = "422"
	ERR_NONICKNAMEGIVEN   = "431"
	ERR_ERRONEUSNICKNAME  = "432"
	ERR_NICKNAMEINUSE     = "433"
	ERR_USERNOTINCHANNEL  = "441"
	ERR_NOTONCHANNEL      = "442"
	ERR_USERONCHANNEL     = "443"
	ERR_NOTREGISTERED     = "451"
	ERR_NEEDMOREPARAMS    = "461"
	ERR_ALREADYREGISTERED = "462"
	ERR_PASSWDMISMATCH    = "464"
	ERR_CHANNELISFULL     = "471"
	ERR_INVITEONLYCHAN    = "473"
	ERR_BANNEDFROMCHAN    = "474"
	ERR_BADCHANNELKEY     = "475"
	ERR_CHANOPRIVSNEEDED  = "482"
)

// Errors
var (
	ErrNickInUse       = errors.New("irc: nickname in use")
	ErrNoSuchNick      = errors.New("irc: no such nick")
	ErrNoSuchChannel   = errors.New("irc: no such channel")
	ErrNotOnChannel    = errors.New("irc: not on channel")
	ErrNotOperator     = errors.New("irc: not operator")
	ErrBannedFromChan  = errors.New("irc: banned from channel")
	ErrInviteOnly      = errors.New("irc: channel is invite only")
	ErrChannelFull     = errors.New("irc: channel is full")
	ErrBadChannelKey   = errors.New("irc: bad channel key")
	ErrNotRegistered   = errors.New("irc: not registered")
)

// User represents a connected IRC user.
type User struct {
	mu sync.RWMutex

	Nick     string
	Username string
	Realname string
	Host     string
	Modes    string
	Away     string

	Channels map[string]*Channel
	Server   *Server
	conn     UserConnection

	registered   bool
	lastActive   time.Time
	lastPing     time.Time
	pingPending  bool
	created      time.Time

	I2PDestination string
}

// UserConnection is the interface for user connections.
type UserConnection interface {
	Send(message string) error
	Close() error
	RemoteAddr() string
}

// Channel represents an IRC channel.
type Channel struct {
	mu sync.RWMutex

	Name      string
	Topic     string
	TopicBy   string
	TopicTime time.Time
	Modes     string
	Key       string
	Limit     int
	Created   time.Time

	Users     map[string]*User
	Operators map[string]bool
	Voiced    map[string]bool
	Bans      []string
	Invites   map[string]bool
}

// Message represents a parsed IRC message.
type Message struct {
	Prefix  string
	Command string
	Params  []string
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Name          string
	Network       string
	MOTD          []string
	MaxNickLen    int
	MaxChannelLen int
	MaxMessageLen int
	MaxChannels   int
	PingInterval  time.Duration
	PingTimeout   time.Duration
	Operators     map[string]string
	Password      string
}

// DefaultServerConfig returns the default server configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Name:          DefaultServerName,
		Network:       DefaultNetwork,
		MOTD:          []string{DefaultMOTD},
		MaxNickLen:    DefaultMaxNickLen,
		MaxChannelLen: DefaultMaxChannelLen,
		MaxMessageLen: DefaultMaxMessageLen,
		MaxChannels:   DefaultMaxChannels,
		PingInterval:  DefaultPingInterval,
		PingTimeout:   DefaultPingTimeout,
		Operators:     make(map[string]string),
	}
}

// NewChannel creates a new channel.
func NewChannel(name string) *Channel {
	return &Channel{
		Name:      name,
		Created:   time.Now(),
		Users:     make(map[string]*User),
		Operators: make(map[string]bool),
		Voiced:    make(map[string]bool),
		Bans:      make([]string, 0),
		Invites:   make(map[string]bool),
	}
}

// NewUser creates a new user.
func NewUser(conn UserConnection, host string) *User {
	return &User{
		Host:       host,
		conn:       conn,
		Channels:   make(map[string]*Channel),
		lastActive: time.Now(),
		created:    time.Now(),
	}
}

// Prefix returns the user's IRC prefix.
func (u *User) Prefix() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.Nick + "!" + u.Username + "@" + u.Host
}

// Send sends a message to the user.
func (u *User) Send(msg string) error {
	u.mu.Lock()
	u.lastActive = time.Now()
	u.mu.Unlock()
	return u.conn.Send(msg)
}

// SendNumeric sends a numeric reply.
func (u *User) SendNumeric(server, numeric, message string) error {
	u.mu.RLock()
	nick := u.Nick
	u.mu.RUnlock()
	if nick == "" {
		nick = "*"
	}
	return u.Send(":" + server + " " + numeric + " " + nick + " " + message)
}

// IsRegistered returns true if the user is registered.
func (u *User) IsRegistered() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.registered
}

// SetRegistered marks the user as registered.
func (u *User) SetRegistered() {
	u.mu.Lock()
	u.registered = true
	u.mu.Unlock()
}

// IsOperator returns true if the user is a server operator.
func (u *User) IsOperator() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return strings.Contains(u.Modes, "o")
}

// AddMode adds a mode to the user.
func (u *User) AddMode(mode rune) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !strings.ContainsRune(u.Modes, mode) {
		u.Modes += string(mode)
	}
}

// RemoveMode removes a mode from the user.
func (u *User) RemoveMode(mode rune) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.Modes = strings.Replace(u.Modes, string(mode), "", 1)
}

// MemberCount returns the number of users in the channel.
func (c *Channel) MemberCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Users)
}

// IsOperator returns true if the user is a channel operator.
func (c *Channel) IsOperator(nick string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Operators[nick]
}

// IsVoiced returns true if the user has voice.
func (c *Channel) IsVoiced(nick string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Voiced[nick]
}

// IsBanned returns true if the mask is banned.
func (c *Channel) IsBanned(mask string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, ban := range c.Bans {
		if matchMask(mask, ban) {
			return true
		}
	}
	return false
}

// IsInvited returns true if the user is invited.
func (c *Channel) IsInvited(nick string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Invites[nick]
}

// HasMode returns true if the channel has the mode.
func (c *Channel) HasMode(mode rune) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return strings.ContainsRune(c.Modes, mode)
}

// GetPrefix returns the prefix for a user in the channel.
func (c *Channel) GetPrefix(nick string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Operators[nick] {
		return "@"
	}
	if c.Voiced[nick] {
		return "+"
	}
	return ""
}

// matchMask checks if a string matches a wildcard mask.
func matchMask(s, mask string) bool {
	if mask == "*" {
		return true
	}
	return strings.HasPrefix(s, strings.TrimSuffix(mask, "*"))
}
