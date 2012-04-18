#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from google.appengine.ext import webapp,db
from google.appengine.ext.webapp import util
from urllib  import urlencode
from urllib2 import urlopen,Request

import urllib2,cookielib
import web
import urllib,hashlib,time,random,hmac,base64,httplib

import pickle
import access_token
import common

consumer_key =''
consumer_secret =''
request_token_path='http://www.douban.com/service/auth/request_token'
access_token_path='http://www.douban.com/service/auth/access_token'
authorize_url = 'http://www.douban.com/service/auth/authorize?oauth_token='

request_tokens = {}
access_tokens = {}

def to_signature_key(method, url, data):
	keys = list(data.keys())
	keys.sort()
	encoded = urllib.quote("&".join([key+"="+data[key] for key in keys]))
	return "&".join([method, urllib.quote(url, safe="~"), encoded])

def request_token_params(consumer_key, consumer_secret, path, method='GET'):
	data={}
	data['oauth_consumer_key']=consumer_key
	data['oauth_signature_method']='HMAC-SHA1'
	data['oauth_timestamp']=str(int(time.time()))
	data['oauth_nonce']=''.join([str(random.randint(0,9)) for i in range(10)])

	msg = to_signature_key(method, path, data)

	signed = base64.b64encode(hmac.new(consumer_secret+"&", msg, hashlib.sha1).digest())

	data['oauth_signature']=signed
	return data

def oauth_header(consumer_key, consumer_secret, oauth_token, oauth_secret, path, realm,method):
    data = access_token.access_token_params(consumer_key, consumer_secret, oauth_token, oauth_secret, path, method=method)
    header_string = ','.join([key+'="'+data[key]+'"' for key in data.keys()])
    return 'OAuth realm="'+realm+'",'+header_string

def result2dict(result_string):
	d = {}
	params = result_string.split('&')
	for p in params:
		d[p.split('=')[0]] = p.split('=')[1]
	return d

class Home:
    def GET(self):
        sid = web.cookies().get('sid')
        if sid :
            user=common.User.get_current_user(sid)
            conn=httplib.HTTPConnection('www.douban.com',80)
            #url = 'http://api.douban.com/miniblog/saying'
            url = 'http://api.douban.com/people/%40me'
            content = """
            <?xml version='1.0' encoding='UTF-8'?>
                       <entry xmlns:ns0="http://www.w3.org/2005/Atom" xmlns:db="http://www.douban.com/xmlns/">
                                  <content>ヾ(￣∇￣=￣∇￣)ﾉ by debug</content>
                       </entry>
            """


            header = {}
            header['Authorization']=oauth_header(consumer_key,consumer_secret,user.oauth_token,user.oauth_token_secret,url,"http://api.douban.com",'GET')
            header['Content-Type']='application/atom+xml'
            conn.request('GET', url, None, header)
            res=conn.getresponse().read()
            conn.close()
            return res
        else:
            #return 'do not have sid'
            raise  web.seeother('login')

class Login:
  def GET(self):
   conn = httplib.HTTPConnection("www.douban.com", 80)
   params = request_token_params(consumer_key, consumer_secret, request_token_path)
   conn.request('GET', request_token_path+"?"+urllib.urlencode(params))
   res = conn.getresponse().read()
   request_token = result2dict(res)
   sess = pickle.dumps(request_token)
   sesspara={}
   sesspara['sesspara']= base64.urlsafe_b64encode(sess)
   web.setcookie('session',sesspara['sesspara'],3600)
   url = authorize_url+request_token['oauth_token']+'&oauth_callback=http://debug.shelfon.tk/run'
   raise web.seeother(url)
   #self.redirect(url)
   #print '<script language=javascript>'
   #url =' self.location="'+authorize_url+request_token['oauth_token']+ '&oauth_callback=http://localhost:8080/access_token;</script>'
   #print url


"""application = webapp.WSGIApplication([
  ('/', Login),
    ('/run',access_token.GetAccess)
], debug=True)"""
urls=(
    "/","Home",
    '/login','Login',
    '/run','access_token.GetAccess'
)
app = web.application(urls, globals())
if __name__ == '__main__':
    #util.run_wsgi_app(application)
    app.cgirun()
    #greeting = common.Greeting()
    #greeting.content = 'o yeah~'
    #greeting.author='shelfon'
    #greeting.put()
    #current_user={'key':'test','sid':'shelfon','oauth_token':'mine','oauth_token_secret':'mine_secret'}
    #common.User.get_new_user(current_user)
    """
    user=common.User.get_user_by_sid('kira')
    user.user=current_user['user']
    user.oauth_token=current_user['oauth_token']
    user.oauth_token_secret=current_user['oauth_token_secret']
    db.put(user)
    test_user=common.User.get_current_user('kira')
    if test_user:
        print test_user.user+test_user.oauth_token
    else :
        test_user=common.User.get_current_user('test')
        if test_user:
            print test_user.user+test_user.oauth_token
        else:
            print 'failed'
     """
    #print user_detail['user']