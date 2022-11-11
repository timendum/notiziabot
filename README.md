# notiziabot

This little go project to allow a team of moderators to post a link with a "community" user.

## Setup

We need *TWO* [Reddit apps](https://www.reddit.com/prefs/apps):

1. One web app to authenticate mods
1. One script app to submit, the developer **must** be the "community" user.

1. Create an `.env` config via `cp .env.template .env`
1. Edit `.env` config with:
   1. `SUBREDDIT=` your subreddit
   1. `LOGLEVEL=` as you wish (2 = Error, 4 = Info, 5 = Debug)
   1. `USERAGENT=` User Anget of your app (Reddit wants it)
   1. `R_CLIENT_ID=` the **script** application ID (something like `abcd0efgh12345`)
   1. `R_CLIENT_SECRET=` the **script** application secret (usually longer then the ID)
   1. `R_USERNAME=` the username of your "community" user
   1. `R_PASSWORD=` the password of your "community" user
   1. `O_CLIENT_ID=` the **web** application ID
   1. `O_CLIENT_SECRET=` the **web** application secret
   1. `O_HOST=` the base url for your **web** application

Note: the `redirect uri` configured in Reddit **must** be `O_HOST` + `\callback`

That's it,
now every moderator of `SUBREDDIT`
with "mail" permission (or "all" permission),
can use the interface to post as `R_USERNAME`.

## Installation

    git clone https://github.com/timendum/notiziabot.git
    cd notiziabot
    go install
    go build
    ./notiziabot

Then expose to the internet port 3000 via Nginx, Apache, Caddy or similar.