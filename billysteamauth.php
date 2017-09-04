<?php
require_once 'openid.php';

if (session_status() == PHP_SESSION_NONE)
    session_start();

class BillySteamAuth
{
    /**
     * The logged in user's SteamID.
     *
     * @var int
     */
    public $SteamID;

    /**
     * The name of the session var to store the user's SteamID in.
     *
     * @var string
     */
    private $session_name;

    /**
     * The OpenID instance used to authenticate users.
     *
     * @var LightOpenID
     */
    private $open_id;

    /**
     * BillySteamAuth constructor.
     *
     * @param string $session_name Name of the session var to store the user's SteamID in
     */
    public function __construct($session_name = 'steam_id')
    {
        $this->session_name = $session_name;

        if (isset($_SESSION[$session_name])) {
            $this->SteamID = $_SESSION[$session_name];
            return;
        }

        $this->open_id = new LightOpenID($_SERVER['HTTP_HOST']);
        $this->open_id->identity = 'https://steamcommunity.com/openid';

        if ($this->open_id->mode) {
            if ($this->open_id->validate()) {
                $this->SteamID = basename($this->open_id->identity);
                $_SESSION[$session_name] = $this->SteamID;
            }
        }

    }

    /**
     * Returns the OAuth redirect URL
     *
     * @return string
     */
    public function LoginURL()
    {
        return $this->open_id->authUrl();
    }

    /**
     * Logs a user out by removing their SteamID from the session array.
     * NOTE: Does not destroy the session!
     *
     * @return void
     */
    public function Logout()
    {
        unset($_SESSION[$this->session_name]);
    }

    /**
     * Strips OpenID parameters from a URL.
     *
     * @param array $get
     *
     * @throws InvalidArgumentException
     *
     * @return string Filtered query string
     */
    public function StripOpenID($get = null)
    {
        if (is_null($get))
            $get = $_GET;
        elseif (!is_array($get))
            throw new InvalidArgumentException('The get argument must be an array.');

        $openID = [
            'openid_ns',
            'openid_sig',
            'openid_mode',
            'openid_signed',
            'openid_identity',
            'openid_return_to',
            'openid_claimed_id',
            'openid_op_endpoint',
            'openid_assoc_handle',
            'openid_response_nonce'
        ];

        $query = [];
        foreach ($get as $key => $value) {
            if (!in_array($key, $openID)) {
                $query[$key] = $value;
            }
        }

        return '?'.http_build_query($query);
    }
}
