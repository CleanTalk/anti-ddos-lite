<?php

/**
 * Cleantalk base class
 *
 * @version 1.0
 * @package Cleantalk
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

function antiDdosProtectionMain($data)
{
    $data['secure_key'] = md5($data['remote_ip'] . ':' . $data['anti_ddos_salt']);
    if ( (antiDdosSkipUserReentry($data) && checkHeadless($data))
            || antiDdosSkipVisitorsFromTrustedAs($data)
            || antiDdosSkipVisitorsFromTrustedUa($data)
    ) {
        //set security cookies
        antiDdosProtectionSetCookie($data['secure_label'], $data['secure_key']);
        return;
    }
    //show debug about headless for blocked visitors
    if ( !empty($data['anti_ddos_debug']) && antiDdosSkipUserReentry($data) && !checkHeadless($data) ) {
        error_log(
            sprintf(
                'Visitor has headless mode: %s.',
                $data['remote_ip']
            )
        );
    }

    antiDdosShowDdosScreenAndRedirect($data);
}

/**
 * Universal method to adding cookies
 * Wrapper for setcookie() Conisdering PHP version
 *
 * @see https://www.php.net/manual/ru/function.setcookie.php
 *
 * @param string $name Cookie name
 * @param string $value Cookie value
 * @param int $expires Expiration timestamp. 0 - expiration with session
 * @param string $path
 * @param string $domain
 * @param bool $secure
 * @param bool $httponly
 * @param string $samesite
 *
 * @return void
 */
function antiDdosProtectionSetCookie(
    $name,
    $value = '',
    $expires = 0,
    $path = '',
    $domain = '',
    $secure = null,
    $httponly = false,
    $samesite = 'Lax'
) {
    if (headers_sent()) {
        return;
    }

    $server_https_flag = isset($_SERVER['HTTPS']) ? $_SERVER['HTTPS'] : '';
    $server_port = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '';

    $secure = ! is_null($secure)
        ? $secure
        : ! in_array($server_https_flag, ['off', '']) || $server_port === 443;

    // For PHP 7.3+ and above
    if ( version_compare(phpversion(), '7.3.0', '>=') ) {
        $params = array(
            'expires' => $expires,
            'path' => $path,
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => $httponly,
        );

        if ($samesite) {
            $params['samesite'] = $samesite;
        }

        /**
         * @psalm-suppress InvalidArgument
         */
        setcookie($name, $value, $params);
        // For PHP 5.6 - 7.2
    } else {
        setcookie($name, $value, $expires, $path, $domain, $secure, $httponly);
    }
}

/**
 * Fire DDoS protection by external signal.
 * -----------------------------------------------------------------------
 * | File anti_ddos_protection_fire.dat must be placed in the site ROOT! |
 * -----------------------------------------------------------------------
 *
 * @return bool
 */
function antiDdosCheckDatFileExist()
{
    return file_exists('anti_ddos_protection_fire.dat');
}

/**
 * @return bool
 */
function antiDdosSkipUserReentry($data)
{
    return isset($_COOKIE[$data['secure_label']]) && $_COOKIE[$data['secure_label']] == $data['secure_key'];
}

/**
 * @return bool
 */
function antiDdosSkipVisitorsFromTrustedAs($data)
{
    if (!function_exists('geoip_org_by_name')) {
        return false;
    }

    // List of trusted Autonomous systems.
    $notRatedAs = [13238,15169,8075,10310,36647,13335,2635,32934,38365,55967,
        16509,2559,19500,47764,17012,1449,43247,32734,15768,33512,18730,30148];

    $visitorOrg = geoip_org_by_name($data['remote_ip']);
    if ($visitorOrg !== false && preg_match("/^AS(\d+)\s/", $visitorOrg, $matches)) {
        foreach ($notRatedAs as $asn) {
            if ($asn == $matches[1]) {
                if ($data['anti_ddos_debug']) {
                    error_log(sprintf('Skip antiddos protection for %s, because it\'s trusted AS%d.', $data['remote_ip'], $asn));
                }

                return true;
            }
        }
    }

    return false;
}

/**
 * @return bool
 */
function antiDdosSkipVisitorsFromTrustedUa($data)
{
    if (!$data['skip_not_rated_ua']) {
        return false;
    }

    if (!isset($_SERVER['HTTP_USER_AGENT'])) {
        return false;
    }

    require "not_rated_ua.php";
    global $notRatedUa;
    if (count($notRatedUa) > 0) {
        foreach ($notRatedUa as $ua) {
            if (preg_match("/^$ua$/", $_SERVER['HTTP_USER_AGENT'])) {
                if ($data['anti_ddos_debug']) {
                    error_log(sprintf('Skip antiddos protection for %s, because it\'s trusted User-Agent %s.', $data['remote_ip'], $ua));
                }
                return true;
            }
        }
    }

    return false;
}

/**
 * Show anti-ddos screen and then redirect.
 * -----------------------------------------------------------------------
 * | File anti_ddos_protection_fire.dat must be placed in the site ROOT! |
 * -----------------------------------------------------------------------
 *
 * @return void
 */
function antiDdosShowDdosScreenAndRedirect($data)
{
    $html_file = file_get_contents(dirname(__FILE__) . '/anti-ddos.html');

    http_response_code(403);

    $code = str_replace('{VISITOR_IP}', $data['remote_ip'], $html_file);
    $code = str_replace('{REDIRECT_DELAY}', $data['redirect_delay'], $code);
    $code = str_replace('{DAYS}', $data['secure_cookie_days'], $code);
    $code = str_replace('{SECURE_LABEL}', $data['secure_label'], $code);
    $code = str_replace('{SECURE_KEY}', $data['secure_key'], $code);
    $code = str_replace('{SERVER_URL}', $data['server_url'], $code);

    echo ($code);

    if ( $data['anti_ddos_debug'] ) {
        error_log(
            sprintf(
                'Blacklisted IP, drop connection %s to %s.',
                $data['remote_ip'],
                $_SERVER['REQUEST_URI']
            )
        );
    }

    exit;
}

function checkRequirements()
{
    if (version_compare(phpversion(), '5.6', '<')) {
        return false;
    }

    return true;
}

function checkHeadless($data)
{
    if ( empty($data['test_headless']) ) {
        return true;
    }


    if ( isset($_COOKIE['ct_headless']) ) {
        $headless = explode(':', base64_decode($_COOKIE['ct_headless']));
        if ( isset($headless[0], $headless[1])
            && $headless[0] === $data['secure_key']
            && $headless[1] === 'false' ) {
            return true;
        }
    }

    return false;
}
