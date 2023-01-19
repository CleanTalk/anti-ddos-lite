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
    
    if (antiDdosSkipUserReentry($data)
        || antiDdosSkipVisitorsFromTrustedAs($data)
        || antiDdosSkipVisitorsFromTrustedUa($data)
    ) {
        return;
    }

    setcookie($data['secure_label'], $data['secure_key'], null, '/');

    antiDdosShowDdosScreenAndRedirect($data);
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
    if (!$data['test_not_rated_ua']) {
        return false;
    }

    if (!isset($_SERVER['HTTP_USER_AGENT'])) {
        return false;
    }

    require "not_rated_ua.php";
    if (count($notRatedUa) > 0) {
        foreach ($notRatedUa as $ua) {
            if (preg_match("/^$ua$/", $_SERVER['HTTP_USER_AGENT'])) {
                if ($anti_ddos_debug) {
                    error_log(sprintf('Skip antiddos protection for %s, because it\'s trusted User-Agent %s.', $remote_ip, $ua));
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

    echo sprintf($html_file, 
        $data['remote_ip'],
        $data['remote_ip'],
        $data['redirect_delay'],
        $data['secure_cookie_days'],
        $data['secure_label'],
        $data['secure_key'],
        $data['redirect_delay'] * 1000
    );

    if ($data['anti_ddos_debug']) {
        error_log(sprintf('Blacklisted IP, drop connection %s to %s.', 
            $data['remote_ip'],
            $_SERVER['REQUEST_URI']
        ));
    }

    exit; 
}