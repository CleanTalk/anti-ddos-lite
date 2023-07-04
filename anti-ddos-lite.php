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

if (!checkRequirements()) {
    return;
}

if (!isset($_SERVER['REMOTE_ADDR'])) {
    return;
}

$data = [
    'anti_ddos_protection_enable' => true, // Switch to control AntiDDoS state.
    'anti_ddos_debug' => true,             // Activate debug statements.
    'skip_not_rated_ua' => false,          // Test visitors against trusted UserAgent's list.
    'secure_cookie_days' => 180,           // Days to use secure cookie.
    'redirect_delay' => 3,                 // Delay in seconds before redirection to original URL.
    'remote_ip' => $_SERVER['REMOTE_ADDR'],
    'secure_label' => 'ct_anti_ddos_key',
    'test_headless' => true,               //block visitors with headless mode (such a selenium)
    'server_url' => isset($_SERVER['HTTPS']) ? 'https://' . $_SERVER['HTTP_HOST'] : 'http://' . $_SERVER['HTTP_HOST'],

    // Secret key salt to avoid copy/past of the Cookie between visitors.
    // ATTENTION!!!
    // YOU MUST GENERATE NEW $anti_ddos_salt BEFORE USE IT ON YOUR OWN SITE.
    // ATTENTION!!!
    'anti_ddos_salt' => '4xU9mn2X7iPZpeW2'
];

if ($data['anti_ddos_protection_enable'] || antiDdosCheckDatFileExist()) {
    antiDdosProtectionMain($data);
}
