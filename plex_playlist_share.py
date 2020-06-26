#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description:  Sync Plex playlists to shared users.
# Author:       /u/SwiftPanda16
# Requires:     plexapi, requests, xmltodict


import requests
import xmltodict
from plexapi.server import PlexServer
import logging
import base64, json, getpass
import http.client
from json import loads
import configparser
import platform
import plex_config


### EDIT SETTINGS ###
logging.basicConfig(level=logging.INFO)

PLEX_URL = 'http://192.168.1.23:32400'
PLAYLISTS = ['Alexis and Elise Favs','Christmas']  # List of playlists to sync
FROM_USER = 'Alexis'
TO_USERS = ['Elise']  # List of users to sync the playlists to


## CODE BELOW ##

def get_plex_token():
    PLATFORM = platform.system()
    PLATFORM_VERSION = platform.release()
    Config = configparser.ConfigParser()

    file = Config.read(plex_config.conf_file)

    ## Auth against plex.tv
    auth = ('%s:%s' % (plex_config.username, plex_config.password)).replace('\n', '')
    base64string = base64.b64encode(auth.encode('ascii'))
    txdata = ''
    headers = {'Authorization': "Basic %s" % base64string.decode('ascii'),
               'X-Plex-Client-Identifier': "Plex Token",
               'X-Plex-Device-Name': "Plex Updater",
               'X-Plex-Product': "Plex Updater",
               'X-Plex-Platform': PLATFORM,
               'X-Plex-Platform-Version': PLATFORM_VERSION,
               'X-Plex-Version': "1.0"}

    conn = http.client.HTTPSConnection("plex.tv")
    conn.request("POST", "/users/sign_in.json", txdata, headers)
    response = conn.getresponse()
    # print(response.status, response.reason)
    data = response.read()

    ## Parse the json and rturn a plex token
    json = loads(data)
    token = json["user"]["authToken"]

    target = open(plex_config.conf_file, 'w')
    Config.set('creds', 'token', token)
    Config.write(target)
    target.close()
    conn.close()
    return token

PLEX_TOKEN =get_plex_token()
logging.info(f'Plex token: {PLEX_TOKEN}')


def fetch_plex_api(path='', method='GET', plextv=False, **kwargs):
    """Fetches data from the Plex API"""

    url = 'https://plex.tv' if plextv else PLEX_URL.rstrip('/')
    headers = {'X-Plex-Token': PLEX_TOKEN,
               'Accept': 'application/json'}

    params = {}
    if kwargs:
        params.update(kwargs)

    try:
        if method.upper() == 'GET':
            r = requests.get(url + path,
                             headers=headers, params=params, verify=False)
        elif method.upper() == 'POST':
            r = requests.post(url + path,
                              headers=headers, params=params, verify=False)
        elif method.upper() == 'PUT':
            r = requests.put(url + path,
                             headers=headers, params=params, verify=False)
        elif method.upper() == 'DELETE':
            r = requests.delete(url + path,
                                headers=headers, params=params, verify=False)
        else:
            logging.error("Invalid request method provided: {method}".format(method=method))
            return

        if r and len(r.content):
            if 'application/json' in r.headers['Content-Type']:
                return r.json()
            elif 'application/xml' in r.headers['Content-Type']:
                return xmltodict.parse(r.content)
            else:
                return r.content
        else:
            return r.content

    except Exception as e:
        logging.error("Error fetching from Plex API: {err}".format(err=e))

def get_user_tokens(server_id):
    api_users = fetch_plex_api('/api/users', plextv=True)
    api_shared_servers = fetch_plex_api('/api/servers/{server_id}/shared_servers'.format(server_id=server_id), plextv=True)
    user_ids = {user['@id']: user.get('@username', user.get('@title')) for user in api_users['MediaContainer']['User']}
    users = {user_ids[user['@userID']]: user['@accessToken'] for user in api_shared_servers['MediaContainer']['SharedServer']}
    return users

def get_playlists_from_user(token):
    plex_user = PlexServer(PLEX_URL, token)
    user_playlists = plex_user.playlists()
    return user_playlists

def sync_all():

    global user_plex
    plex = PlexServer(PLEX_URL, PLEX_TOKEN)
    plex_users = get_user_tokens(plex.machineIdentifier)
    user_token = plex_users.get(FROM_USER)
    playlists_to_sync = get_playlists_from_user(user_token)
    for playlist in playlists_to_sync:
        playlist_items = playlist.items()
        for user in TO_USERS:
            user_token = plex_users.get(user)
            user_plex = PlexServer(PLEX_URL, user_token)
            # Delete the old playlist
            try:
                logging.info(f'Syncing Playlist {playlist.title} to user {user}')
                user_playlist = user_plex.playlist(playlist.title)
                user_playlist.delete()
            except Exception as e:
                logging.error(e)
            try:
                user_plex.createPlaylist(title=playlist.title, items=playlist_items)
            except Exception as e:
                logging.error(e)

def main():
    """Main script"""
    sync_all()
    return

if __name__ == "__main__":
    main()
    logging.info("Done.")
