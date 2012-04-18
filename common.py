# -*- coding: UTF-8 -*-
__author__ = 'Shelfon'

from google.appengine.api import users, memcache, mail
from google.appengine.ext import db, deferred

class Greeting(db.Model):
    author=db.UserProperty()
    content = db.StringProperty(multiline=True)
    tags = db.ListProperty(db.Key, "Tags")

class User(db.Model):
    sid=db.StringProperty(required=True)
    name =db.StringProperty()
    oauth_token=db.StringProperty()
    oauth_token_secret=db.StringProperty()
    def to_dict(self):
        return{
            'key':self.key().name(),
            'sid':self.sid,
            'name':self.name,
            'oauth_token':self.oauth_token,
            'oauth_token_secret':self.oauth_token_secret
        }
    @classmethod
    def from_dict(cls,entity):
        return cls(
            key_name=entity['key'],
            sid=entity['sid'],
            name=entity['name'],
            oauth_token=entity['oauth_token'],
            oauth_token_secret=entity['oauth_token_secret']
        )
    @staticmethod
    def get_current_user(sid):
        user = User.get_by_key_name(sid)
        return user
    @staticmethod
    #@memcache('get_user_by_sid',USER_CACHE_TIME,lambda sid:sid)
    def get_user_by_sid(sid):
        try:
           user = User.get_by_key_name(sid)
           return user if user else User.get_or_insert(key_name=sid,sid=sid)
        except:
            def save_user(sid):
                User.get_or_insert(key_name=sid,user=sid)
            deferred.defer(save_user,sid)
            return User(key_name=sid,user=sid)
    @staticmethod
    def get_new_user(user):
        temp=User.get_user_by_sid(user['sid'])
        temp.oauth_token=user['oauth_token']
        temp.oauth_token_secret=user['oauth_token_secret']
        db.put(temp)
    @staticmethod
    def update_user_data(user):
        temp=User.get_current_user(user['sid'])
        temp.oauth_token=user['oauth_token']
        temp.oauth_token_secret=user['oauth_token_secret']
        db.put(temp)