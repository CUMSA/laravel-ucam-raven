<?php
// vi: tabstop=8 shiftwidth=8 bs=2

// This PHP module implements an agent for the University of Cambridge
// Web Authentication System
//
// See http://raven.cam.ac.uk/ for more details
//
// Copyright (c) 2004, 2005, 2008 University of Cambridge
//
// This module is free software; you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as
// published by the Free Software Foundation; either version 2.1 of the
// License, or (at your option) any later version.
//
// The module is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this toolkit; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
// USA
//
// $Id: ucam_webauth.php,v 1.3 2013/04/11 21:48:55 jes91 Exp $
//
// Version 0.52
// Adapted for Laravel 5.2 by Daniel Wong, based on Gideon Farrell's modifications.

use Log;

class UcamWebauth {
    // Placing the key in the file since it has never changed, and should be
    // versioned controlled.
    private $RAVEN_KEY = "-----BEGIN CERTIFICATE-----
MIIDrTCCAxagAwIBAgIBADANBgkqhkiG9w0BAQQFADCBnDELMAkGA1UEBhMCR0Ix
EDAOBgNVBAgTB0VuZ2xhbmQxEjAQBgNVBAcTCUNhbWJyaWRnZTEgMB4GA1UEChMX
VW5pdmVyc2l0eSBvZiBDYW1icmlkZ2UxKDAmBgNVBAsTH0NvbXB1dGluZyBTZXJ2
aWNlIFJhdmVuIFNlcnZpY2UxGzAZBgNVBAMTElJhdmVuIHB1YmxpYyBrZXkgMjAe
Fw0wNDA4MTAxMzM1MjNaFw0wNDA5MDkxMzM1MjNaMIGcMQswCQYDVQQGEwJHQjEQ
MA4GA1UECBMHRW5nbGFuZDESMBAGA1UEBxMJQ2FtYnJpZGdlMSAwHgYDVQQKExdV
bml2ZXJzaXR5IG9mIENhbWJyaWRnZTEoMCYGA1UECxMfQ29tcHV0aW5nIFNlcnZp
Y2UgUmF2ZW4gU2VydmljZTEbMBkGA1UEAxMSUmF2ZW4gcHVibGljIGtleSAyMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/9qcAW1XCSk0RfAfiulvTouMZKD4j
m99rXtMIcO2bn+3ExQpObbwWugiO8DNEffS7bzSxZqGp7U6bPdi4xfX76wgWGQ6q
Wi55OXJV0oSiqrd3aOEspKmJKuupKXONo2efAt6JkdHVH0O6O8k5LVap6w4y1W/T
/ry4QH7khRxWtQIDAQABo4H8MIH5MB0GA1UdDgQWBBRfhSRqVtJoL0IfzrSh8dv/
CNl16TCByQYDVR0jBIHBMIG+gBRfhSRqVtJoL0IfzrSh8dv/CNl16aGBoqSBnzCB
nDELMAkGA1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxEjAQBgNVBAcTCUNhbWJy
aWRnZTEgMB4GA1UEChMXVW5pdmVyc2l0eSBvZiBDYW1icmlkZ2UxKDAmBgNVBAsT
H0NvbXB1dGluZyBTZXJ2aWNlIFJhdmVuIFNlcnZpY2UxGzAZBgNVBAMTElJhdmVu
IHB1YmxpYyBrZXkgMoIBADAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUAA4GB
AFciErbr6zl5i7ClrpXKA2O2lDzvHTFM8A3rumiOeauckbngNqIBiCRemYapZzGc
W7fgOEEsI4FoLOjQbJgIrgdYR2NIJh6pKKEf+9Ts2q/fuWv2xOLw7w29PIICeFIF
hAM+a6/30F5fdkWpE1smPyrfASyXRfWE4Ccn1RVgYX9u
-----END CERTIFICATE-----";

    var $PROTOCOL_VERSION = '1';
    var $SESSION_TICKET_VERSION = '1';
    var $DEFAULT_AUTH_SERVICE = 'https://raven.cam.ac.uk/auth/authenticate.html';
    var $DEFAULT_KEY_DIR = 'keys';
    var $DEFAULT_COOKIE_NAME = 'Ucam-WebAuth-Session';
    var $DEFAULT_TIMEOUT_MESSAGE = 'your logon to the site has expired';
    var $DEFAULT_HOSTNAME = NULL; // must be supplied explicitly
    var $COMPLETE = 1;
    var $TESTSTRING = 'Test';
    var $WLS_LOGOUT = 'Not-authenticated';

    // array index constants

    var $SESSION_TICKET_VER = 0;
    var $SESSION_TICKET_STATUS = 1;
    var $SESSION_TICKET_MSG = 2;
    var $SESSION_TICKET_ISSUE = 3;
    var $SESSION_TICKET_EXPIRE = 4;
    var $SESSION_TICKET_ID = 5;
    var $SESSION_TICKET_PRINCIPAL = 6;
    var $SESSION_TICKET_AUTH = 7;
    var $SESSION_TICKET_SSO = 8;
    var $SESSION_TICKET_PARAMS = 9;
    var $SESSION_TICKET_SIG = 10;

    var $WLS_TOKEN_VER = 0;
    var $WLS_TOKEN_STATUS = 1;
    var $WLS_TOKEN_MSG = 2;
    var $WLS_TOKEN_ISSUE = 3;
    var $WLS_TOKEN_ID = 4;
    var $WLS_TOKEN_URL = 5;
    var $WLS_TOKEN_PRINCIPAL = 6;
    var $WLS_TOKEN_AUTH = 7;
    var $WLS_TOKEN_SSO = 8;
    var $WLS_TOKEN_LIFE = 9;
    var $WLS_TOKEN_PARAMS = 10;
    var $WLS_TOKEN_KEYID = 11;
    var $WLS_TOKEN_SIG = 12;

    var $do_session;
    var $cookie_key;
    var $cookie_path;
    var $session_ticket;
    var $auth_service;
    var $description;
    var $response_timeout;
    var $clock_skew;
    var $hostname;
    var $key_dir;
    var $max_session_life;
    var $timeout_message;
    var $cookie_name;
    var $cookie_domain;
    var $fail;
    //var $status;
    //var $headers;
    var $forced_reauth_message;
    var $interact;

    var $error_message = array('200' => 'OK',
        '410' => 'Authentication cancelled at user\'s request',
        '510' => 'No mutually acceptable types of authentication available',
        '520' => 'Unsupported authentication protocol version',
        '530' => 'Parameter error in authentication request',
        '540' => 'Interaction with the user would be required',
        '550' => 'Web server and authentication server clocks out of sync',
        '560' => 'Web server not authorized to use the authentication service',
        '570' => 'Operation declined by the authentication service');

    function __construct($args) {
        if (isset($args['auth_service'])) {
            $this->auth_service = $args['auth_service'];
        } else {
            $this->auth_service = $this->DEFAULT_AUTH_SERVICE;
        }

        if (isset($args['description'])) {
            $this->description = $args['description'];
        }

        if (isset($args['response_timeout'])) {
            $this->response_timeout = $args['response_timeout'];
        } else {
            $this->response_timeout = 30;
        }

        if (isset($args['clock_skew'])) {
            $this->clock_skew = $args['clock_skew'];
        } else {
            $this->clock_skew = 5;
        }

        if (isset($args['key_dir'])) {
            $this->key_dir = $args['key_dir'];
        } else {
            $this->key_dir = $this->DEFAULT_KEY_DIR;
        }

        if (isset($args['do_session'])) {
            $this->do_session = $args['do_session'];
        } else {
            $this->do_session = TRUE;
        }

        if (isset($args['max_session_life'])) {
            $this->max_session_life = $args['max_session_life'];
        } else {
            $this->max_session_life = 2 * 60 * 60;
        }

        if (isset($args['timeout_message'])) {
            $this->timeout_message = $args['timeout_message'];
        } else {
            $this->timeout_message = $this->DEFAULT_TIMEOUT_MESSAGE;
        }

        if (isset($args['cookie_key'])) {
            $this->cookie_key = $args['cookie_key'];
        }

        if (isset($args['cookie_name'])) {
            $this->cookie_name = $args['cookie_name'];
        } else {
            $this->cookie_name = $this->DEFAULT_COOKIE_NAME;
        }

        if (isset($args['cookie_path'])) {
            $this->cookie_path = $args['cookie_path'];
        } else {
            $this->cookie_path = '';
        }
        // *** SHOULD BE PATH RELATIVE PATH TO SCRIPT BY DEFAULT ***

        if (isset($args['hostname'])) {
            $this->hostname = $args['hostname'];
        } else {
            $this->hostname = $this->DEFAULT_HOSTNAME;
        }

        // COOKIE PATH CAN BE NULL, DEFAULTS TO CURRENT DIRECTORY (TEST)

        if (isset($args['cookie_domain'])) {
            $this->cookie_domain = $args['cookie_domain'];
        } else {
            $this->cookie_domain = '';
        }

        if (isset($args['fail'])) {
            $this->fail = $args['fail'];
        } else {
            $this->fail = '';
        }

        if (isset($args['forced_reauth_message'])) {
            $this->forced_reauth_message = $args['forced_reauth_message'];
        }

        if (isset($args['interact'])) {
            $this->interact = $args['interact'];
        }

        if (isset($args['request'])) {
            $this->request = $args['request'];
        } else {
            $this->request = request();
        }

        if (isset($args['url_callback'])) {
            $this->url_callback = $args['url_callback'];
        } else {
            $this->url_callback = $this->hostname . '/auth/raven/callback';
        }
    }

    // get/set functions for agent attributes

    function auth_service($arg = NULL) {
        if (isset($arg)) {
            $this->auth_service = $arg;
        }

        return $this->auth_service;
    }

    function description($arg = NULL) {
        if (isset($arg)) {
            $this->description = $arg;
        }

        return $this->description;
    }

    function response_timeout($arg = NULL) {
        if (isset($arg)) {
            $this->response_timeout = $arg;
        }

        return $this->response_timeout;
    }

    function clock_skew($arg = NULL) {
        if (isset($arg)) {
            $this->clock_skew = $arg;
        }

        return $this->clock_skew;
    }

    function key_dir($arg = NULL) {
        if (isset($arg)) {
            $this->key_dir = $arg;
        }

        return $this->key_dir;
    }

    function do_session($arg = NULL) {
        if (isset($arg)) {
            $this->do_session = $arg;
        }

        return $this->do_session;
    }

    function max_session_life($arg = NULL) {
        if (isset($arg)) {
            $this->max_session_life = $arg;
        }

        return $this->max_session_life;
    }

    function timeout_message($arg = NULL) {
        if (isset($arg)) {
            $this->timeout_message = $arg;
        }

        return $this->timeout_message;
    }

    function cookie_key($arg = NULL) {
        if (isset($arg)) {
            $this->cookie_key = $arg;
        }

        return $this->cookie_key;
    }

    function cookie_name($arg = NULL) {
        if (isset($arg)) {
            $this->cookie_name = $arg;
        }

        return $this->cookie_name;
    }

    function cookie_path($arg = NULL) {
        if (isset($arg)) {
            $this->cookie_path = $arg;
        }

        return $this->cookie_path;
    }

    function cookie_domain($arg = NULL) {
        if (isset($arg)) {
            $this->cookie_domain = $arg;
        }

        return $this->cookie_domain;
    }

    function fail($arg = NULL) {
        if (isset($arg)) {
            $this->fail = $arg;
        }

        return $this->fail;
    }

    function hostname($arg = NULL) {
        if (isset($arg)) {
            $this->hostname = $arg;
        }

        return $this->hostname;
    }

    function forced_reauth_message($arg = NULL) {
        if (isset($arg)) {
            $this->forced_reauth_message = $arg;
        }

        return $this->forced_reauth_message;
    }

    function interact($arg = NULL) {
        if (isset($arg)) {
            $this->interact = $arg;
        }

        return $this->interact;
    }

    // read-only functions to access the authentication state

    function status() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_STATUS])) {
            return $this->session_ticket[$this->SESSION_TICKET_STATUS];
        }

        return NULL;
    }

    function success() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_STATUS])) {
            return ($this->session_ticket[$this->SESSION_TICKET_STATUS] == '200');
        }

        return NULL;
    }

    function msg() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_MSG])) {
            return $this->session_ticket[$this->SESSION_TICKET_MSG];
        }

        return NULL;
    }

    function issue() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_ISSUE])) {
            return $this->session_ticket[$this->SESSION_TICKET_ISSUE];
        }

        return NULL;
    }

    function expire() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_EXPIRE])) {
            return $this->session_ticket[$this->SESSION_TICKET_EXPIRE];
        }

        return NULL;
    }

    function id() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_ID])) {
            return $this->session_ticket[$this->SESSION_TICKET_ID];
        }

        return NULL;
    }

    function principal() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_PRINCIPAL])) {
            return $this->session_ticket[$this->SESSION_TICKET_PRINCIPAL];
        }

        return NULL;
    }

    function auth() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_AUTH])) {
            return $this->session_ticket[$this->SESSION_TICKET_AUTH];
        }

        return NULL;
    }

    function sso() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_SSO])) {
            return $this->session_ticket[$this->SESSION_TICKET_SSO];
        }

        return NULL;
    }

    function params() {
        if (isset($this->session_ticket[$this->SESSION_TICKET_PARAMS])) {
            return $this->session_ticket[$this->SESSION_TICKET_PARAMS];
        }

        return NULL;
    }

    // authentication functions

    function using_https() {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on");
    }

    function check_sig($data, $sig, $key_id) {

        // **** TODO : remove trailing slash from key_dir

        // Ensure keyid only contains digits (protect against path traversal)
        if (preg_match('/^[1-9][0-9]{0,7}$/', $key_id) !== 1) {
            Log::error('UcamWebauth: Invalid key identifier in response message');
            return false;
        }
        // $key_filename = $this->key_dir . '/' . $key_id . '.crt';
        // $key_file = fopen($key_filename, 'r');
        // Band-aid test for the most obvious cause of error - whole
        // thing needs improvement
        // if (!$key_file) {
        //     Log::alert('UcamWebauth: Failed to open key file ', ['keyfile' => $key_filename]);
        //     return false;
        // }
        // $key_str = fread($key_file, filesize($key_filename));
        $key = openssl_get_publickey($this->RAVEN_KEY);
        // fclose($key_file);
        $result = openssl_verify(rawurldecode($data), $this->wls_decode(rawurldecode($sig)), $key);
        openssl_free_key($key);
        return $result;
    }

    function hmac_sha1($key, $data) {
        $blocksize = 64;
        if (strlen($key) > $blocksize) {
            $key = pack('H*', sha1($key));
        }

        $key = str_pad($key, $blocksize, chr(0x00));
        $ipad = str_repeat(chr(0x36), $blocksize);
        $opad = str_repeat(chr(0x5c), $blocksize);
        $hmac = pack('H*', sha1(($key ^ $opad) . pack('H*', sha1(($key ^ $ipad) . $data))));
        return $this->wls_encode(bin2hex($hmac));
    }

    function hmac_sha1_verify($key, $data, $sig) {
        return ($sig == $this->hmac_sha1($key, $data));
    }

    function url() {
        // $hostname = urlencode($this->hostname);
        // $port = $_SERVER{'SERVER_PORT'};
        // if ($this->using_https()) {
        //     $protocol = 'https://';
        //     if ($port == '443') {
        //         $port = '';
        //     }

        // } else {
        //     $protocol = 'http://';
        //     if ($port == '80') {
        //         $port = '';
        //     }

        // }
        // $port = urlencode($port); // should be redundant, of course
        // $url = $protocol . $hostname;
        // if ($port != '') {
        //     $url .= ':' . $port;
        // }

        // /*$url .= $_SERVER['SCRIPT_NAME'];
        // if (isset($_SERVER['PATH_INFO'])) $url .= $_SERVER['PATH_INFO'];
        // if (isset($_SERVER['QUERY_STRING']) and $_SERVER['QUERY_STRING'] != '')
        // {
        // $url .= '?' . $_SERVER['QUERY_STRING'];
        // } */

        // // jes91: must remove /webroot/ because Cake's mod_rewrite will trip over
        // // if an attempt is made to literally access a Cake controller. Easiest
        // // way to do this is to just use REQUEST_URI.
        // // In any case, can't see why you would not want to use
        // // REQUEST_URI in all circumstances, at least on Apache v2.
        // $url .= $_SERVER['REQUEST_URI'];
        // return $url;
        return url()->current();
    }

    function full_cookie_name() {
        if ($this->using_https()) {
            return $this->cookie_name . '-S';
        }
        return $this->cookie_name;
    }

    function time2iso($t) {
        //return gmstrftime('%Y%m%d', $t).'T'.gmstrftime('%H%M%S', $t).'Z';
        return gmdate('Ymd\THis\Z', $t);
    }

    function iso2time($t) {
        return gmmktime(substr($t, 9, 2),
            substr($t, 11, 2),
            substr($t, 13, 2),
            substr($t, 4, 2),
            substr($t, 6, 2),
            substr($t, 0, 4),
            -1);
    }

    function wls_encode($str) {
        $result = base64_encode($str);
        $result = preg_replace(array('/\+/', '/\//', '/=/'), array('-', '.', '_'), $result);
        return $result;
    }

    function wls_decode($str) {
        $result = preg_replace(array('/-/', '/\./', '/_/'), array('+', '/', '='), $str);
        $result = base64_decode($result);
        return $result;
    }

    function get_cookie() {
        return $this->request->cookie($this->full_cookie_name());
    }

    // function authenticate($authassertionid = NULL, $testauthonly = NULL) {
    //     // consistency check

    //     if ($testauthonly and !$this->do_session) {
    //         $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
    //         $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Requested dummy run but session cookie not managed';
    //         return TRUE;
    //     }

    // // check that someone defined cookie key and if we are doing session management

    // if ($this->do_session and !isset($this->cookie_key)) {
    //     $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
    //     $this->session_ticket[$this->SESSION_TICKET_MSG] = 'No key defined for session cookie';
    //     return TRUE;
    // }

    // Commented out because not using session management.
    // // Check that the hostname is set explicitly (since we cannot trust
    // // the Host: header); if it returns false (i.e. not set).

    // if (!isset($this->hostname) or $this->hostname == '') {
    //     $this->session_ticket[$this->SESSION_TICKET_MSG] =
    //         'Ucam_Webauth configuration error - mandatory hostname not defined';
    //     $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
    //     Log::error('UcamWebauth: hostname not set in Ucam_Webauth object, but is mandatory');
    //     return TRUE;
    // }

    // /* FIRST: if we are doing session management then see if we already
    //  * have authentication data stored in a cookie. Note that if the
    //  * stored status isn't 200 (OK) then we destroy the cookie so that if
    //  * we come back through here again we will fall through and repeat
    //  * the authentication. We do this first so that replaying an old
    //  * authentication response won't trigger a 'stale authentication' error
    //  */

    // Log::debug('UcamWebauth: FIRST STAGE');

    // $current_timeout_message = NULL;

    // if ($this->do_session) {

    //     Log::debug('UcamWebauth: session management ON');

    //     if (!is_null($this->get_cookie()) and
    //         $this->get_cookie() != $this->TESTSTRING and
    //         $this->get_cookie() != $this->WLS_LOGOUT) {

    //         Log::info('UcamWebauth: existing authentication cookie found',
    //             ['cookie' => rawurldecode($this->get_cookie());

    //         //$old_cookie = explode(' ', rawurldecode($this->get_cookie()));
    //         //$this->session_ticket = explode('!', $old__cookie[0]);
    //         $this->session_ticket = explode('!', rawurldecode($this->get_cookie()));

    //         $values_for_verify = $this->session_ticket;
    //         $sig = array_pop($values_for_verify);

    //         if ($this->hmac_sha1_verify($this->cookie_key,
    //             implode('!', $values_for_verify),
    //             $sig)) {

    //             Log::debug('UcamWebauth: existing authentication cookie verified');

    //             $issue = $this->iso2time($this->session_ticket[$this->SESSION_TICKET_ISSUE]);
    //             $expire = $this->iso2time($this->session_ticket[$this->SESSION_TICKET_EXPIRE]);
    //             $now = time();

    //             if ($issue <= $now and $now < $expire) {
    //                 if (!isset($authassertionid) or $authassertionid != $this->session_ticket[$this->SESSION_TICKET_ID]) {
    //                     if ($this->session_ticket[$this->SESSION_TICKET_STATUS] != '200') {
    //                         if (!$testauthonly) {
    //                             cookie()->forget($this->full_cookie_name())->queue();
    //                         }

    //                     }
    //                     Log::debug('UcamWebauth: AUTHENTICATION COMPLETE');
    //                     return TRUE;
    //                 } else {
    //                     $current_timeout_message = $this->forced_reauth_message;
    //                     Log::notice('UcamWebauth: detection of \'stale\' authassertionid requested and found', ['authassertionid' => $authassertionid]);
    //                     Log::notice('UcamWebauth: authentication using current session ticket denied');
    //                 }
    //             } else {
    //                 $current_timeout_message = $this->timeout_message;
    //                 Log::info('UcamWebauth: local session cookie expired', ['issue' => $issue, 'now' => $now, 'expire' => $expire]);
    //             }
    //         } else {
    //             Log::notice('UcamWebauth: AUTHENTICATION FAILED, session cookie sig invalid');
    //             $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Session cookie signature invalid';
    //             $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
    //             return TRUE;
    //         }
    //     }
    // }

    function callback() {
        /* SECOND: Look to see if we are being invoked as the callback from
         * this WLS. If so, validate the response. If we are not doing session
         * management then we can then just return. If we are doing session
         * management, check that the session cookie already exists with a
         * test value (becuause otherwise we probably don't have cookies
         * enabled), set it, and redirect back to the original URL to clear
         * the browser's location bar of the WLS response.
         */

        Log::debug('UcamWebauth: SECOND STAGE');

        $token = NULL;

        if (isset($_SERVER['QUERY_STRING']) and
            preg_match('/^WLS-Response=/', $_SERVER['QUERY_STRING'])) {

            Log::debug('UcamWebauth: WLS response', ['wls' => $_SERVER['QUERY_STRING']]);

            // does this change QUERY_STRING??:
            $token = explode('!', preg_replace('/^WLS-Response=/', '', rawurldecode($_SERVER['QUERY_STRING'])));

            $this->session_ticket[$this->SESSION_TICKET_STATUS] = '200';
            $this->session_ticket[$this->SESSION_TICKET_MSG] = '';

            $sig = array_pop($token);
            $key_id = array_pop($token);

            if ($token[$this->WLS_TOKEN_VER] != $this->PROTOCOL_VERSION) {
                $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Wrong protocol version in authentication service reply';
                $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
            } else if ($token[$this->WLS_TOKEN_STATUS] != '200') {
                $this->session_ticket[$this->SESSION_TICKET_MSG] = $this->error_message[$token[$this->WLS_TOKEN_STATUS]];
                if (isset($token[$this->WLS_TOKEN_MSG])) {
                    $this->session_ticket[$this->SESSION_TICKET_MSG] .= $token[$this->WLS_TOKEN_MSG];
                }

                $this->session_ticket[$this->SESSION_TICKET_STATUS] = $token[$this->WLS_TOKEN_STATUS];
            } else if ($this->check_sig(implode('!', $token), $sig, $key_id) != 1) {
                $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Invalid WLS token signature';
                $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
                throw new Exception("Invalid WLS token signature");
                return null;
            } else {
                $now = time();
                $issue = $this->iso2time($token[$this->WLS_TOKEN_ISSUE]);

                if (!isset($issue)) {
                    $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Unable to read issue time in authentication service reply';
                    $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
                } else if ($issue > $now + $this->clock_skew + 1) {
                    $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Authentication service reply aparently issued in the future: ' . $token[$this->WLS_TOKEN_ISSUE];
                    $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
                } else if ($now - $this->clock_skew - 1 > $issue + $this->response_timeout) {
                    $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Stale authentication service reply issue at ' . $token[$this->WLS_TOKEN_ISSUE];
                    $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
                }

                $response_url = $token[$this->WLS_TOKEN_URL];
                $response_url = preg_replace('/\?.*$/', '', $response_url);
                $this_url = preg_replace('/\?.+$/', '', $this->url());

                if ($this_url != $response_url) {
                    $this->session_ticket[$this->SESSION_TICKET_MSG] = 'URL in response ticket doesn\'t match this URL: ' . $response_url . ' != ' . $this_url;
                    $this->session_ticket[$this->SESSION_TICKET_STATUS] = '600';
                }
            }

            // work out session expiry time

            $expiry = $this->max_session_life;
            if (isset($token[$this->WLS_TOKEN_LIFE]) and $token[$this->WLS_TOKEN_LIFE] > 0 and $token[$this->WLS_TOKEN_LIFE] < $expiry) {
                $expiry = $token[$this->WLS_TOKEN_LIFE];
            }

            // populate session ticket with information collected so far

            $this->session_ticket[$this->SESSION_TICKET_ISSUE] = $this->time2iso(time());
            $this->session_ticket[$this->SESSION_TICKET_EXPIRE] = $this->time2iso(time() + $expiry);
            $this->session_ticket[$this->SESSION_TICKET_ID] = $token[$this->WLS_TOKEN_ID];
            $this->session_ticket[$this->SESSION_TICKET_PRINCIPAL] = $token[$this->WLS_TOKEN_PRINCIPAL];
            $this->session_ticket[$this->SESSION_TICKET_AUTH] = $token[$this->WLS_TOKEN_AUTH];
            $this->session_ticket[$this->SESSION_TICKET_SSO] = $token[$this->WLS_TOKEN_SSO];
            $this->session_ticket[$this->SESSION_TICKET_PARAMS] = $token[$this->WLS_TOKEN_PARAMS];

            // return complete if we are not doing session management

            // if (!$this->do_session) {
            //     return TRUE;
            // }

            // // otherwise establish a session cookie to maintain the
            // // session ticket. First check that the cookie actually exists
            // // with a test value, because it should have been created
            // // previously and if its not there we'll probably end up in
            // // a redirect loop.

            // if (!isset($this->get_cookie()) or
            //     $this->get_cookie() != $this->TESTSTRING) {
            //     $this->session_ticket[$this->SESSION_TICKET_STATUS] = '610';
            //     $this->session_ticket[$this->SESSION_TICKET_MSG] = 'Browser is not accepting session cookie';
            //     return TRUE;
            // }

            // $this->session_ticket[$this->SESSION_TICKET_VER] = $this->SESSION_TICKET_VERSION;

            // // This used to use ksort and implode, but appeared to produce
            // // broken results from time to time. This does the work the hard
            // // way.

            // $cookie = '';
            // for ($i = 0; $i < $this->SESSION_TICKET_PARAMS; $i++) {
            //     if (isset($this->session_ticket[$i])) {
            //         $cookie .= $this->session_ticket[$i];
            //     }

            //     $cookie .= '!';
            // }
            // if (isset($this->session_ticket[$this->SESSION_TICKET_PARAMS])) {
            //     $cookie .= $this->session_ticket[$this->SESSION_TICKET_PARAMS];
            // }

            // $sig = $this->hmac_sha1($this->cookie_key, $cookie);
            // $cookie .= '!' . $sig;
            // Log::debug('UcamWebauth: cookie', ['cookie' => $cookie]);

            // // End

            // if (!$testauthonly) {
            //     cookie($this->full_cookie_name(),
            //         $cookie,
            //         0,
            //         $this->cookie_path,
            //         $this->cookie_domain,
            //         $this->using_https())->queue();
            // }

            // Log::debug('UcamWebauth: session cookie established, redirecting...');

            // // Clean up the URL in browser location bar, i.e., remove WLS stuff
            // // in query string, and, inevitably, redo original request a second time?
            // if (!$testauthonly) {
            //     return redirect()->to($token[$this->WLS_TOKEN_URL], 302, [], $this->using_https());
            // }

            // return FALSE;
        } else {
            throw new Exception("Could not find WLS response");
            return null;
        }
    }

    function redirect() {
        /* THIRD: send a request to the WLS. If we are doing session
         * management then set a test value cookie so we can test that
         * it's still available when we get back.
         */

        Log::debug('UcamWebauth: THIRD STAGE');

        // log a warning if being used to authenticate POST requests
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            Log::warning('UcamWebauth: PHP Agent invoked for POST request, which it does\'nt really support');
        }

        // if ($this->do_session) {
        //     // If the hostname from the request (Host: header) does not match the
        //     // server's preferred name for itself (which should be what's configured
        //     // as hostname), cookies are likely to break "randomly" (or more
        //     // accurately, the cookie may not be sent by the browser since it's for
        //     // a different hostname) as a result of following links that use the
        //     // preferred name, or server-level redirects e.g. to fix "directory"
        //     // URLs lacking the trailing "/". Attempt to avoid that by redirecting
        //     // to an equivalent URL using the configured hostname.

        //     if (isset($_SERVER['HTTP_HOST']) and (strtolower($this->hostname) !=
        //         strtolower($_SERVER['HTTP_HOST']))) {
        //         Log::warning('UcamWebauth: Redirect to tidy up hostname mismatch');
        //         if (!$testauthonly) {
        //             return redirect()->to($this->url(), 302, [], $this->using_https());
        //         }

        //         return FALSE;
        //     }

        //     Log::debug('UcamWebauth: setting pre-session cookie');
        //     if (!$testauthonly) {
        //         cookie($this->full_cookie_name(),
        //             $this->TESTSTRING,
        //             0,
        //             $this->cookie_path,
        //             $this->cookie_domain,
        //             $this->using_https())->queue();
        //     }

        // }

        $dest = $this->auth_service .
        '?ver=' . $this->PROTOCOL_VERSION .
        '&url=' . rawurlencode($this->url_callback);
        if (isset($this->description)) {
            $dest .= '&desc=' . rawurlencode($this->description);
        }

        //if (isset($this->aauth)) $dest .= '&aauth=' . rawurlencode($this->aauth);
        if (isset($this->interact)) {
            $dest .= '&iact=' . ($this->interact == TRUE ? 'yes' : 'no');
        }

        if (isset($this->params)) {
            $dest .= '&params' . rawurlencode($this->params);
        }

        if (isset($current_timeout_message)) {
            $dest .= '&msg=' . rawurlencode($current_timeout_message);
        }

        if (isset($this->clock_skew)) {
            $dest .= '&date=' . rawurlencode($this->time2iso(time())) .
            '&skew=' . rawurlencode($this->clock_skew);
        }
        if ($this->fail == TRUE) {
            $dest .= '&fail=yes';
        }

        Log::debug('UcamWebauth: redirecting...');

        // if (!$testauthonly) {
        return redirect()->to($dest, 302, [], $this->using_https());
        // }

        // return FALSE;
    }
}
?>
