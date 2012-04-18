# -*- coding: UTF-8 -*- 
__author__ = 'Shelfon'
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from urllib  import urlencode
from urllib2 import urlopen,Request
import urllib2
import web
import webbrowser
import encodings
import urllib,hashlib,time,random,hmac,base64,httplib
import pickle
from common import User

consumer_key ='0cf3228173b52f6d26d967845b1f8e47'
consumer_secret ='58940995526395fa'

access_token_path='http://www.douban.com/service/auth/access_token'
def to_signature_key(method, url, data):
	keys = list(data.keys())
	keys.sort()
	encoded = urllib.quote("&".join([key+"="+data[key] for key in keys]))
	return "&".join([method, urllib.quote(url, safe="~"), encoded])
def result2dict(result_string):
	d = {}
	params = result_string.split('&')
	for p in params:
		d[p.split('=')[0]] = p.split('=')[1]
	return d
def access_token_params(consumer_key, consumer_secret, oauth_token, oauth_token_secret, path, method='GET'):
    data={}
    data['oauth_consumer_key']=consumer_key
    data['oauth_signature_method']='HMAC-SHA1'
    data['oauth_timestamp']=str(int(time.time()))
    data['oauth_nonce']=''.join([str(random.randint(0,9)) for i in range(10)])
    data['oauth_token'] = oauth_token
    msg = to_signature_key(method, path, data)
    #print msg
    signed = base64.b64encode(hmac.new(consumer_secret+"&"+oauth_token_secret, msg, hashlib.sha1).digest())
    #print signed
    data['oauth_signature']=signed
    return data

class GetAccess:
  def GET(self):
      conn = httplib.HTTPConnection("www.douban.com", 80)
      #cur_url = self.request('/run')
      cur_url = web.cookies().get('session')
      #cur_url = self.request.str_GET['sesspara']
      #request_token={}
      request_token =  pickle.loads(base64.urlsafe_b64decode(cur_url))
      params = access_token_params(consumer_key, consumer_secret, request_token['oauth_token'],request_token['oauth_token_secret'], access_token_path)
      conn.request('GET', access_token_path+"?"+urllib.urlencode(params))
      res = conn.getresponse().read()
      if res != 'Unauthorized Request Token':
          access_token = result2dict(res)
          access_token['sid']=access_token['douban_user_id']
          if access_token :
              current = User.get_current_user(access_token['sid'])
              if current:
                  User.update_user_data(access_token)
              else:
                  User.get_new_user(access_token)
              current=User.get_current_user(access_token['sid'])
              if current:
                  web.setcookie('sid',current.sid,expires=86400)
                  return current.sid
              else:
                  return '更新用户失败'
          else:
              return'获得认证失败'
      else:
          return '用户未授权'
if __name__ == '__main__':
    print 'hi'
#    conn = httplib.HTTPConnection("www.douban.com", 80)
    #params = access_token_params(consumer_key, consumer_secret, 'e75aa32d8911d90eb60fe9889b358b2a','50792986cbc7d1be', access_token_path)