# oaquery

Query OpenArena / RatArena servers

## Usage

Query a specific server:

```
oaquery.py example.com
```

You can specify multiple servers as well as alternative ports:

```
oaquery.py oa1.example.com oa2.example.com:27961
```

By default, empty servers are excluded. Use `--empty` if you want to show them:

```
oaquery.py --empty oa1.example.com
```

Sort servers by the number of players:

```
oaquery.py --sort oa1.example.com
```

To query all servers that are registered on a master server, use:

```
oaquery.py -a dpmaster.deathmask.net
```

`dpmaster.deathmask.net` is the master server that OA uses

Display all options:

```
oaquery.py -h
```
