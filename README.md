# Anti-DDoS-Lite (Anti-Crawler app)

[![Build Status](https://travis-ci.org/CleanTalk/anti-ddos-lite.svg?branch=master)](https://travis-ci.org/CleanTalk/anti-ddos-lite)

A small PHP app to protect your site against DDoS attack or crawling web site by bots.

## Description
Most of bots can't execute JavaScript code or can execute code partiraly. This app filters traffic from bots by using simple JavaScript code. Bots are denied to read original pages, they get only a single stop-page. As result DDoS attack is reduced by elemenation of bots traffic that participating in the DDoS attack.

In the same time, legitimate/real visitors get original page after short delay because the browser of legitimate/real visitors executes JavaScript code. The legitimate/real visitors see the stop-page only once, during first visit to the site.

<img src="images/stop-page.png" >

## How to use

1. Include the app as first line in index.php.
```php
<?php
require "anti-ddos-lite/anti-ddos-lite.php";

//
// index.php code bellow
// ...
//

?>
```

2. Generate new value for $secure_cookie_salt. 

## Skip protection for visitors from trusted networks, Autonomous systesm (AS)
Setup [GeoIP](https://www.php.net/manual/en/book.geoip.php) and list excluded Autonomous systems in the $not_rated_as.
```
  $not_rated_as = '';
```

## Skip trusted User-Agents
Skip trusted User-Agents. Regular expressions are allowed, example is bellow.
```
  $not_rated_ua = array(
        'CleanTalk Uptime bot.+',
        'Googlebot', 
        'Bingbot',
        'Baiduspider',
        'YandexBot',
        'facebot',
        'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        'ia_archiver'
);
```


## Contacts
Email: welcome@cleantalk.org
