<?php

/**
 * Cleantalk base class
 *
 * @version 2.0.2
 * @package Cleantalk
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (https://cleantalk.org)
 * @license MIT License 2022
 *
 */

require 'src/anti-ddos-lib.php';

/**
 * Check application requirements.
 */
if (!checkRequirements()) {
    return;
}

/**
 * Application settings.
 */
$data = [
    // Switch to control AntiDDoS state.
    'anti_ddos_protection_enable' => true,
    // Activate debug statements.
    'anti_ddos_debug' => true,
    // Do not check visitors from trusted UserAgent list. Set the list in the file not_rated_ua.php
    'skip_not_rated_ua' => false,
    // Do not check visitors from trusted AS list. Set the list in the file not_rated_as.php
    'skip_not_rated_as' => false,
    // Days to use secure cookie.
    'secure_cookie_days' => 180,
    // Delay in seconds before redirection to original URL.
    'redirect_delay' => 3,
    // Source of visitor's IP. ATTENTION! Application will not start if this setting is empty.
    'remote_ip' => $_SERVER['REMOTE_ADDR'],
    // Name of secure label
    'secure_label' => 'ct_anti_ddos_key',
    //block visitors with headless mode (such a selenium)
    'test_headless' => true,
    // Source of server_url
    'server_url' => isset($_SERVER['HTTPS']) ? 'https://' . $_SERVER['HTTP_HOST'] : 'http://' . $_SERVER['HTTP_HOST'],
    // Secret key salt to avoid copy/past of the Cookie between visitors.
    // ATTENTION!!!
    // YOU MUST GENERATE NEW $anti_ddos_salt BEFORE USE IT ON YOUR OWN SITE.
    // ATTENTION!!!
    'anti_ddos_salt' => '4xU9mn2X7iPZpeW2'
];

if (empty($data('remote_ip'))) {
    return;
}

if ($data['anti_ddos_protection_enable'] || antiDdosCheckDatFileExist()) {
    antiDdosProtectionMain($data);
}
