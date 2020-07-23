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

// Switch to control AntiDDoS state.
$anti_ddos_protection_enable = true;
// Activate debug statements.
$anti_ddos_debug = false;
// Test visitors against trusted UserAgent's list.
$test_not_rated_ua = false;

//
// Fire DDoS protection by external signal.
//
// File must be placed in the site ROOT!
$anti_ddos_protection_enable_ext_file = 'anti_ddos_protection_fire.dat';
if ($anti_ddos_protection_enable === false && isset($anti_ddos_protection_enable_ext_file) && file_exists($anti_ddos_protection_enable_ext_file)) {
    $anti_ddos_protection_enable = true;
}

if ($anti_ddos_protection_enable && isset($_SERVER['REMOTE_ADDR'])) {

    // List of trusted Autonomous systems.
    $not_rated_as = '13238,15169,8075,10310,36647,13335,2635,32934,38365,55967,16509,2559,19500,47764,17012,1449,43247,32734,15768,33512,18730,30148';

    $remote_ip = $_SERVER['REMOTE_ADDR'];
    $secure_cookie_label = 'ct_anti_ddos_key';

    // Secret key salt to avoid copy/past of the Cookie between visitors.
    // ATTENTION!!!
    // YOU MUST GENERATE NEW $security_cookie_salt BEFORE USE IT ON YOUR OWN SITE.
    // ATTENTION!!! 
    $secure_cookie_salt = '4xU9mn2X7iPZpeW2';

    $secure_cookie_key = md5($remote_ip . ':' . $secure_cookie_salt);

    // Days to use secure cookie.
    $secure_cookie_days = 180;
    // Delay in seconds before redirection to original URL.
    $redirect_delay = 3;
    
    $test_ip = true;
    $set_secure_cookie = true;
    if (isset($_COOKIE[$secure_cookie_label]) && $_COOKIE[$secure_cookie_label] == $secure_cookie_key) {
        $test_ip = false;
        $set_secure_cookie = false;
    }
    //
    // Skiping visitors from trusted AS 
    // Example: Google, Microsoft and etc.
    //
    $skip_trusted = false;
    if ($test_ip && function_exists('geoip_org_by_name')) {
        $visitor_org = geoip_org_by_name($remote_ip);
        if ($visitor_org !== false && preg_match("/^AS(\d+)\s/", $visitor_org, $matches)) {
            $not_rated_as = explode(",", $not_rated_as);
            foreach ($not_rated_as as $asn) {
                if ($skip_trusted) {
                    continue;
                }
                if ($asn == $matches[1]) {
                    $skip_trusted = true;
                }
            }
            if ($skip_trusted) {
                if ($anti_ddos_debug) {
                    error_log(sprintf('Skip antiddos protection for %s, because it\'s trusted AS%d.', $remote_ip, $asn));
                }
                $test_ip = false;
            }
        }
    }
		
    //
    // Skip trusted User-Agents. Regular expressions are allowed.
    // Example: CleanTalk Uptime bot.+ 
    //
    if ($test_ip === true && $test_not_rated_ua === true) {
        require "not_rated_ua.php"; 
        if (isset($_SERVER['HTTP_USER_AGENT']) && count($not_rated_ua) > 0) {
            foreach ($not_rated_ua as $ua) {
                if (preg_match("/^$ua$/", $_SERVER['HTTP_USER_AGENT'])) {
                    if ($anti_ddos_debug) {
                        error_log(sprintf('Skip antiddos protection for %s, because it\'s trusted User-Agent %s.', $remote_ip, $ua));
                    }
                    $test_ip = false;
                }
            }
        }
    }

    $run_stop_action = $test_ip;
    if ($run_stop_action) {
        $html_file = file_get_contents(dirname(__FILE__) . '/anti-ddos.html');
        echo sprintf($html_file, 
            $remote_ip,
            $remote_ip,
            $redirect_delay,
            $secure_cookie_days,
            $secure_cookie_label,
            $secure_cookie_key,
            $redirect_delay * 1000
        );
        if ($anti_ddos_debug) {
            error_log(sprintf('Blacklisted IP, drop connection %s to %s.', 
                $remote_ip,
                $_SERVER['REQUEST_URI']
            ));
        }

        exit; 
    } 
    if ($set_secure_cookie && !$run_stop_action) {
        setcookie($secure_cookie_label, $secure_cookie_key, null, '/');
    }
}

?>
