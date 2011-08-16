"""
Foursquare API Python module
by John Wiseman <jjwiseman@gmail.com>

Based on a Fire Eagle module by Steve Marshall <steve@nascentguruism.com>.

Example usage:

* No authentication

>>> import foursquare
>>> fs = foursquare.Foursquare()
>>> fs.cities()
{'cities': [{'geolat': 52.378900000000002, 'name': 'Amsterdam', ...}]}

* OAuth

Without a callback URL:

>>> import foursquare
>>> credentials = foursquare.OAuthCredentials(oauth_key, oauth_secret)
>>> fs = foursquare.Foursquare(credentials)
>>> app_token = fs.request_token()
>>> auth_url = fs.authorize(app_token)
>>> print "Go to %s and authorize, then continue." % (auth_url,)
>>> user_token = fs.access_token(app_token, oauth_verifier)
>>> credentials.set_access_token(user_token)
>>> fs.user()
{'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}
"""

import httplib
import urllib
import string
import sys
import logging
import base64
import pprint

import oauth

try:
    # Python 2.6?
    import json
    simplejson = json
except ImportError:
    try: 
        # Have simplejson?
        import simplejson
    except ImportError:
        # Have django or are running in the Google App Engine?
        from django.utils import simplejson


# General API setup
API_PROTOCOL = 'https'
API_SERVER   = 'api.foursquare.com'
API_VERSION  = 'v2'
API_DATE_VERIFIED = "20110808"

OAUTH_SERVER = 'foursquare.com'


# Calling templates
API_BASE=API_PROTOCOL + '://' + API_SERVER + '/' + API_VERSION
API_URL_TEMPLATE   = string.Template(
    API_BASE + '/${method}.json'
)
API_URL_TEMPLATE_WITH_ID   = string.Template(
    API_BASE + '/${method}/${id}.json'
)

API_URL_TEMPLATE_ASPECT   = string.Template(
    API_BASE + '/${method}/${id}/${method2}.json'
)

OAUTH_URL_TEMPLATE = string.Template(
    API_PROTOCOL + '://' + OAUTH_SERVER + '/oauth2/${method}'
)


POST_HEADERS = {
    'Content-type': 'application/x-www-form-urlencoded',
    'Accept'      : 'text/plain'
}


FOURSQUARE_METHODS = {}

pp = pprint.PrettyPrinter()

def def_method(name, endpoint=None, auth_required=False, server=API_SERVER,
               http_method="GET", optional=[], required=[],
               returns=None, url_template=API_URL_TEMPLATE,
               namespaced=True, remap_function=None, remap_method=None):
    if not endpoint: endpoint = name
    FOURSQUARE_METHODS[name] = {
        'endpoint': endpoint,
        'server': server,
        'http_method': http_method,
        'optional': optional,
        'required': required,
        'returns': returns,
        'url_template': url_template,
        'namespaced':namespaced,
        'remap_function':remap_function,
        'remap_method':remap_method
        }

# --------------------
# OAuth methods
# --------------------

def remap_authenticate(kwargs):
    if not kwargs.get('response_type'):
        kwargs['response_type'] = 'token'
    return kwargs

def_method('authenticate',
            server=OAUTH_SERVER,
            required=['redirect_uri', 'response_type', 'client_id', 'client_secret'],
            returns='request_url',
            remap_function=remap_authenticate,
            url_template=OAUTH_URL_TEMPLATE)

def remap_access_token(kwargs):
    if not kwargs.get('grant_type'):
        kwargs['grant_type'] = 'authorization_code'
    return kwargs

def_method('access_token',
           server=OAUTH_SERVER,
           required=['code', 'client_id', 'client_secret', 'redirect_uri'],
           optional=['grant_type'],
           returns='oauth_token',
           remap_function=remap_access_token,
           url_template=OAUTH_URL_TEMPLATE,
           namespaced=False)


# --------------------
# User methods
# --------------------

def_method('users',
            required=['id', 'oauth_token'],
            url_template=API_URL_TEMPLATE_WITH_ID)


def_method('users_leaderboard',
            required=['oauth_token'],
            optional=['neighbors'])

def_method('users_search',
            required=['oauth_token'],
            optional=['phone', 'email', 'twitter', 'twitterSource', 'fbid', 'name'])


def_method('users_requests',
            required=['oauth_token'])

def_method('users_badges',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_checkins',
            required=['oauth_token', 'id'],
            optional=['limit', 'offset', 'afterTimestamp', 'beforeTimestamp'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_friends',
            required=['oauth_token', 'id'],
            optional=['limit', 'offset'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_mayorships',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_tips',
            required=['oauth_token', 'id'],
            optional=['sort', 'll', 'limit', 'offset'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_todos',
            required=['oauth_token', 'id'],
            optional=['sort', 'll'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_venuehistory',
            required=['oauth_token', 'id'],
            optional=['beforeTimestamp', 'afterTimestamp', 'categoryId'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_request',
            http_method='POST',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_unfriend',
            http_method='POST',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_approve',
            http_method='POST',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_deny',
            http_method='POST',
            required=['oauth_token', 'id'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_setpings',
            http_method='POST',
            required=['oauth_token', 'value'],
            url_template=API_URL_TEMPLATE_ASPECT)

def_method('users_update',
            http_method='POST',
            required=['oauth_token', 'photo'],
            url_template=API_URL_TEMPLATE_ASPECT)

# --------------------
# Venue methods
# --------------------


def_method('venues',
           required=['id'],
           url_template=API_URL_TEMPLATE_WITH_ID)

def_method('venues_add',
           http_method='POST',
           required=['oauth_token', 'name', 'll'],
           optional=['address', 'crossStreet', 'city', 'state', 'zip', 'phone', 'twitter', 'primaryCategoryId'])

def_method('venues_categories')

def_method('venues_explore',
           required=['ll'],
           optional=['llAcc', 'alt', 'altAcc', 'radius', 'section', 'query', 'limit', 'intent'])

def_method('venues_search',
            required=['ll'],
            optional=['llAcc','alt','altAcc','query','limit','intent','categoryId','url','providerId','linkedId'])

def_method('venues_trending',
           required=['ll'],
           optional=['limit', 'radius'])

def_method('venues_herenow',
           required=['id'],
           optional=['limit', 'offset', 'afterTimestamp'],
           url_template=API_URL_TEMPLATE_ASPECT)

def_method('venues_tips',
           required=['id'],
           optional=['sort', 'limit', 'offset'],
           url_template=API_URL_TEMPLATE_ASPECT)

def_method('venues_photos',
           required=['id', 'group'],
           optional=['limit', 'offset'],
           url_template=API_URL_TEMPLATE_ASPECT)

def_method('venues_links',
           required=['id'],
           url_template=API_URL_TEMPLATE_ASPECT)

# --------------------
# Check in methods
# --------------------


def_method('checkins',
           required=['oauth_token', 'id'],
           optional=['signature'],
           url_template=API_URL_TEMPLATE_WITH_ID)

def_method('checkins_add',
           http_method='POST',
           required=['oauth_token'],
           optional=['venueId', 'venue', 'shout', 'broadcast', 'll', 'llAcc', 'alt', 'altAcc'])

def_method('checkins_recent',
           required=['oauth_token'],
           optional=['ll', 'limit', 'afterTimestamp'])

def_method('checkins_addcomment',
           http_method='POST',
           url_template=API_URL_TEMPLATE_ASPECT,
           required=['oauth_token', 'id'],
           optional=['text'])

def_method('checkins_deletecomment',
           http_method='POST',
           url_template=API_URL_TEMPLATE_ASPECT,
           required=['id'],
           optional=['commentId'])

# --------------------
# Tips methods
# --------------------

def_method('tips',
           url_template=API_URL_TEMPLATE_WITH_ID,
           required=['id'])

def_method('tips_add',
           http_method='POST',
           required=['oauth_token', 'venueId', 'text'],
           optional=['url', 'broadcast'])

def_method('tips_search',
           required=['ll'],
           optional=['limit', 'offset', 'filter', 'query'])

def_method('tips_marktodo',
           http_method='POST',
           url_template=API_URL_TEMPLATE_ASPECT,
           required=['oauth_token','id'])

def_method('tips_markdone',
           http_method='POST',
           required=['oauth_token', 'id'])

def_method('unmark',
           http_method='POST',
           required=['oauth_token', 'id'])

# --------------------
# Photos
# --------------------

def_method('photos',
           url_template=API_URL_TEMPLATE_WITH_ID,
           required=['oauth_token', 'id'])

def_method('photos_add',
           http_method='POST',
           required=['oauth_token'],
           optional=['checkinId', 'tipId', 'venueId', 'broadcast', 'public', 'll', 'llAcc', 'alt', 'altAcc', 'photo'])

# --------------------
# Settings
# --------------------

def_method('settings',
           url_template=API_URL_TEMPLATE_WITH_ID,
           required=['oauth_token', 'id'])

def_method('settings_set',
           http_method='POST',
           url_template=API_URL_TEMPLATE_ASPECT,
           required=['oauth_token', 'id', 'value'],
           optional=['message'])

# --------------------
# Specials
# --------------------

def_method('specials',
           url_template=API_URL_TEMPLATE_WITH_ID,
           required=['oauth_template', 'id', 'venueId'])

def_method('specials_search',
           optional=['ll', 'llAcc', 'alt', 'altAcc', 'limit'])

def_method('specials_flag',
           http_method='POST',
           url_template=API_URL_TEMPLATE_WITH_ID,
           required=['oauth_token', 'id', 'venueId', 'problem'],
           optional=['text'])



#TODO: multi-query


class FoursquareException(Exception):
    pass

class FoursquareRemoteException(FoursquareException):
    def __init__(self, method, code, msg):
        self.method = method
        self.code = code
        self.msg = msg

    def __str__(self):
        return 'Error signaled by remote method %s: %s (%s)' % (self.method, self.msg, self.code)



# Used as a proxy for methods of the Foursquare class; when methods
# are called, __call__ in FoursquareAccumulator is called, ultimately
# calling the foursquare_obj's callMethod()
class FoursquareAccumulator:
    def __init__(self, foursquare_obj, name):
        self.foursquare_obj = foursquare_obj
        self.name = name
    
    def __repr__(self):
        return self.name
    
    def __call__(self, *args, **kw):
        return self.foursquare_obj.call_method(self.name, *args, **kw)
    

class Foursquare:
    token=None
    
    def __init__(self, consumer_key, consumer_secret, callback_uri=None, access_token=None):
        # Prepare object lifetime variables
        self.client_id=consumer_key
        self.client_secret=consumer_secret
        self.redirect_uri=callback_uri
        self.token=access_token

        # Prepare the accumulators for each method
        for method in FOURSQUARE_METHODS:
            if not hasattr(self, method):
                setattr(self, method, FoursquareAccumulator(self, method))

    def set_access_token(self, access_token):
        self.token = access_token

    def get_http_connection(self, server):
        if API_PROTOCOL=='https':
            return httplib.HTTPSConnection(server)
        else:
            return httplib.HTTPConnection(server)
        
    
    def fetch_response(self, server, http_method, url, body=None, headers=None):
        """Pass a request to the server and return the response as a
        string.
        """
        http_connection = self.get_http_connection(server)

        # Prepare the request
        if (body is not None) or (headers is not None):
            http_connection.request(http_method, url, body, merge_dicts(POST_HEADERS, headers))
        else:
            http_connection.request(http_method, url)
        
        # Get the response
        response = http_connection.getresponse()
        response_body = response.read()

        # If we've been informed of an error, raise it
        if response.status != 200:
            raise FoursquareRemoteException(url, response.status, response_body)
        
        # Return the body of the response
        return response_body
    

    def call_method(self, method, *args, **kw):
        logging.debug('Calling foursquare method %s %s %s' % (method, args, kw))
        
        # Theoretically, we might want to do 'does this method exits?'
        # checks here, but as all the aggregators are being built in
        # __init__(), we actually don't need to: Python handles it for
        # us.
        meta = FOURSQUARE_METHODS[method]
        
        if args:
            # Positional arguments are mapped to meta['required'] and
            # meta['optional'] in order of specification of those
            # (with required first, obviously)
            names = meta['required'] + meta['optional']
            if len(args) > len(names):
                raise FoursquareException('Too many arguments supplied to method %s; ' % (method) + \
                                          'required arguments are %s., optional arguments are %s.' % \
                                          (', '.join(meta['required']),
                                           ', '.join(meta['optional'])))
            for i in xrange(len(args)):
                if not kw.get(names[i]):
                    kw[names[i]] = args[i]

        return self.do_method(method, kw)

    def do_method(self, method, kw):
        meta = FOURSQUARE_METHODS[method]

        if meta['remap_function']:
            remap_function = meta['remap_function']
            new_kw = remap_function(kw)
        else:
            new_kw=kw

        if meta['remap_method']:
            return self.do_method(meta['remap_method'], new_kw)

        #see if we have the arg stored as a member variable
        for arg in (set(meta['required']) | set(meta['optional'])):
            if not arg in kw and arg=='oauth_token' and self.token and len(self.token)>0:
                kw['oauth_token'] = self.token
            elif not arg in kw and getattr(self, arg, None):
                kw[arg] = getattr(self, arg)

        # Check we have all required arguments
        if len(set(meta['required']) - set(kw.keys())) > 0:
            raise FoursquareException('Too few arguments were supplied for the method %s; required arguments are %s and got just %s.' % (method, ', '.join(meta['required']), str(kw)))

        # Check that we don't have extra arguments.
        for arg in kw:
            if (not arg in meta['required']) and (not arg in meta['optional']):
                raise FoursquareException('Unknown argument %s supplied to method %s; ' % \
                                          (arg, method) + \
                                          'required arguments are %s., optional arguments are %s.' % \
                                          (', '.join(meta['required']),
                                           ', '.join(meta['optional'])))

        # Build the request.
        if meta['namespaced']:
            new_method=method.replace('_', '/')
        else:
            new_method=method

        if meta['url_template'] == API_URL_TEMPLATE_WITH_ID:
            url = meta['url_template'].substitute(method=new_method, id=kw['id'])
            del kw['id']
        elif meta['url_template'] == API_URL_TEMPLATE_ASPECT:
            method_parts = new_method.split('/')
            url = meta['url_template'].substitute(method=method_parts[0], method2=method_parts[1], id=kw['id'])
            del kw['id']
        else:
            url = meta['url_template'].substitute(method=new_method)

        kw['v']=API_DATE_VERIFIED

        if 'access_token' not in kw:
            if 'client_id' not in kw:
                kw['client_id'] = self.client_id
            if 'client_secret' not in kw:
                kw['client_secret'] = self.client_secret

        # If the return type is the request_url, simply build the URL and
        # return it witout executing anything
        if 'returns' in meta and meta['returns'] == 'request_url':
            url += "?"+urllib.urlencode(kw)
            return url

        server = API_SERVER
        if 'server' in meta:
            server = meta['server']

        if meta['http_method'] == 'POST':
            logging.info("Getting url "+url+" with body "+str(kw))
            response = self.fetch_response(server, meta['http_method'], url, body=kw)
        else:
            url += "?"+urllib.urlencode(kw)
            logging.info("Getting url "+url)
            response = self.fetch_response(server, meta['http_method'], url)

        if method=='access_token':
            results = simplejson.loads(response)
            self.token=results['access_token']

        # Method returns nothing, but finished fine
        # Return the oauth token
        if 'returns' in meta and meta['returns'] == 'oauth_token':
            return self.token

        results = simplejson.loads(response)
        return results

            

# TODO: Cached version

def merge_dicts(a, b):
    if a == None:
        return b
    if b == None:
        return a

    r = {}
    for key, value in a.items():
        r[key] = value
    for key, value in b.items():
        r[key] = value
    return r


def history_generator(fs, batchsize=250, sinceid=0):
    """A lower-level function for retrieving a user's entire checkin
    history.  Given a Foursquare API object, this function will call
    the object's history method as many times as required to retrieve
    the user's entire history, yielding the result after each call.

    The batchsize argument, which defaults to 250, is the number of
    checkins to attempt to fetch each time.  The sinceid argument,
    which defaults to 0, is the lower bound on desired checkins.

    The idea of making this a generator is to give the caller control
    over the API calls being made--The caller can decide how quickly
    to make calls, or can stop making calls entirely if enough of the
    user's history has been retrieved.
    """
    done = False
    while not done:
        # Get a batch of checkins and yield it.
        h = fs.history(sinceid=sinceid, l=batchsize)
        if h['checkins']:
            h['checkins'] = sorted(h['checkins'], key=lambda c: c['id'])
        yield h

        # Annoying that Foursquare uses null/None to indicate zero
        # checkins.
        if not h['checkins'] or len(h['checkins']) != batchsize:
            done = True
        else:
            # Find the most recent checkin ID.
            sinceid = h['checkins'][-1]['id']


def all_history(fs, batchsize=250, sinceid=0):
    """Returns a tuple containing a user's entire checkin history.
    Note that the result is a tuple, not a dictionary with a single
    key/value containing the list of checkins like the
    Foursquare.history method returns.

    The batchsize argument, which defaults to 250, is the number of
    checkins to attempt to fetch each time.  The sinceid argument,
    which defaults to 0, is the lower bound on desired checkins.
    """
    history = []
    for h in history_generator(fs, batchsize=batchsize, sinceid=sinceid):
        # Annoying that Foursquare uses null/None to indicate zero
        # checkins.
        if h['checkins']:
            history += h['checkins']
    return history
