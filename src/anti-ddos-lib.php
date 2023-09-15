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
    if ( antiDdosSkipUserReentry($data) && !checkHeadless($data) ) {
        writeLog(
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
    if ( headers_sent() ) {
        return;
    }

    $server_https_flag = isset($_SERVER['HTTPS']) ? $_SERVER['HTTPS'] : '';
    $server_port = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '';

    $secure = !is_null($secure)
        ? $secure
        : !in_array($server_https_flag, ['off', '']) || $server_port === 443;

    // For PHP 7.3+ and above
    if ( version_compare(phpversion(), '7.3.0', '>=') ) {
        $params = array(
            'expires' => $expires,
            'path' => $path,
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => $httponly,
        );

        if ( $samesite ) {
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
    require_once "not_rated_as.php";
    global $notRatedAs;

    if ( empty($data['skip_not_rated_as']) || empty($notRatedAs) ) {
        return false;
    }

    $visitorOrg = false;

    if ( $data['way_to_get_asn'] === 'ipinfo' ) {
        $ip_info_org = get_visitor_org_via_ip_info($data['remote_ip'], $data['ip_info_token']);
        if ( !$ip_info_org['success'] ) {
            writeLog(sprintf(
                'Can not get ASN for the IP via get_visitor_org_via_ip_info(): %s, reason: %s',
                $data['remote_ip'],
                $ip_info_org['result']
            ));
        } else {
            $visitorOrg = $ip_info_org['result'];
        }
    } elseif ( $data['way_to_get_asn'] === 'geoip' ) {
        $visitorOrg = function_exists('geoip_org_by_name') ? geoip_org_by_name($data['remote_ip']) : false;
        if ( !$visitorOrg ) {
            writeLog(sprintf('Can not get ASN for the IP via geoip_org_by_name(): %s.', $data['remote_ip']));
        }
    } else {
        writeLog(sprintf('No ASN getting way selected in the config, IP will be checked: %s', $data['remote_ip']));
    }

    if ( $visitorOrg !== false && preg_match("/^AS(\d+)\s/", $visitorOrg, $matches) ) {
        foreach ( $notRatedAs as $asn ) {
            if ( $asn == $matches[1] ) {
                writeLog(sprintf('Skip antiddos protection for %s, because it\'s trusted AS%d.', $data['remote_ip'], $asn));
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
    require_once "not_rated_ua.php";
    global $notRatedUa;

    if ( empty($data['skip_not_rated_ua']) || empty($notRatedUa) ) {
        return false;
    }

    if ( !isset($_SERVER['HTTP_USER_AGENT']) ) {
        return false;
    }

    if ( count($notRatedUa) > 0 ) {
        foreach ( $notRatedUa as $ua ) {
            if ( preg_match("/^$ua$/", $_SERVER['HTTP_USER_AGENT']) ) {
                writeLog(sprintf('Skip antiddos protection for %s, because it\'s trusted User-Agent %s.', $data['remote_ip'], $ua));
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

    echo($code);

    writeLog(
        sprintf(
            'Blacklisted IP, drop connection %s to %s.',
            $data['remote_ip'],
            $_SERVER['REQUEST_URI']
        )
    );

    exit;
}

function checkRequirements()
{
    if ( version_compare(phpversion(), '5.6', '<') ) {
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

function get_visitor_org_via_ip_info($ip, $token = '')
{
    $token = $token !== '' ? '?token=' . $token : '';
    $out = array(
        'success' => false,
        'result' => '',
    );

    try {
        $ch = curl_init('https://ipinfo.io/' . $ip . $token);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        $response_json = curl_exec($ch);
        curl_close($ch);
        $response = json_decode($response_json, true);

        if ( !empty($response['org']) ) {
            $out['success'] = true;
            $out['result'] = $response['org'];
        } elseif ( !empty($response['bogon']) ) {
            $out['result'] = 'Address is bogon.';
        } else {
            $out['result'] = 'No data found to parse from response: ' . $response_json;
        }

        return $out;
    } catch ( \Exception $e ) {
        $out['result'] = 'Unexpected internal error.';
    }
    return $out;
}

function writeLog($msg)
{
    global $data;
    if ( !empty($data['anti_ddos_debug']) && !empty($msg) ) {
        error_log($msg);
    }
}
