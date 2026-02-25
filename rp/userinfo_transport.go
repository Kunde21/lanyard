package rp

// UserInfoTokenTransport controls where the access token is sent for UserInfo requests.
type UserInfoTokenTransport string

const (
	// UserInfoTokenTransportHeader sends the access token in Authorization header.
	UserInfoTokenTransportHeader UserInfoTokenTransport = "header"
	// UserInfoTokenTransportBody sends the access token in form body.
	UserInfoTokenTransportBody UserInfoTokenTransport = "body"
)

func normalizeUserInfoTokenTransport(transport UserInfoTokenTransport) UserInfoTokenTransport {
	switch transport {
	case UserInfoTokenTransportBody:
		return UserInfoTokenTransportBody
	case UserInfoTokenTransportHeader:
		fallthrough
	default:
		return UserInfoTokenTransportHeader
	}
}
