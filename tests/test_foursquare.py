import unittest
import time
from getpass import getpass
import logging
import foursquare
import os

import urlparse

TEST_OAUTH = False

MY_COORDS = [34.09075, -118.27516]


class TestFoursquare(unittest.TestCase):
    maxDiff = None
        
    def setUp(self):
        self.assertIsNotNone(FOURSQUARE_CONSUMER_KEY)
        self.assertTrue(len(FOURSQUARE_CONSUMER_KEY)>0)

        self.assertIsNotNone(FOURSQUARE_CONSUMER_SECRET)
        self.assertTrue(len(FOURSQUARE_CONSUMER_SECRET)>0)

        self.assertIsNotNone(FOURSQUARE_OAUTH_CALLBACK)
        self.assertTrue(len(FOURSQUARE_OAUTH_CALLBACK)>0)

        global FOURSQUARE_ACCESS_TOKEN
        if not FOURSQUARE_ACCESS_TOKEN:
            fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET,
                                   callback_uri=FOURSQUARE_OAUTH_CALLBACK)
            auth_url = fs.authenticate(response_type='token')
            access_token = raw_input('\nPlease go the following URL and authorize your app:\n\n%s\n\nEnter the access_token in the url it redirects you to and press enter: ' % (auth_url,))
            FOURSQUARE_ACCESS_TOKEN = access_token

        self.assertIsNotNone(FOURSQUARE_ACCESS_TOKEN)
        self.assertTrue(len(FOURSQUARE_ACCESS_TOKEN)>0)


    def test_unauthenticated(self):
        "Testing unauthenticated methods."
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)

        venues = fs.venues_search(str(MY_COORDS[0])+','+str(MY_COORDS[1]))
        self.failUnless('venues' in venues['response'])
        local_cafe = find_if(venues['response']['venues'], lambda o: o['id'] == '49d7d4b2f964a5206a5d1fe3')
        self.failUnless(local_cafe)

        self.assertRaises(foursquare.FoursquareException, lambda: fs.users_friends(id='self'))
    
    def test_oauth_authenticate_url(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET,
                                   callback_uri=FOURSQUARE_OAUTH_CALLBACK)
        #test token
        auth_url = fs.authenticate()
        parse_result = urlparse.urlparse(auth_url)
        self.assertEqual('foursquare.com', parse_result.netloc)
        self.assertEqual('https', parse_result.scheme)
        self.assertEqual('/oauth2/authenticate', parse_result.path)
        qs_parse_result = urlparse.parse_qs(parse_result.query)
        self.assertEqual(
            {'client_secret':[FOURSQUARE_CONSUMER_SECRET],'client_id':[FOURSQUARE_CONSUMER_KEY],
             'redirect_uri':[FOURSQUARE_OAUTH_CALLBACK], 'v':['20110808'], 'response_type':['token']},
            qs_parse_result)

        #test code, overriding default args
        auth_url = fs.authenticate(redirect_uri=FOURSQUARE_OAUTH_CALLBACK, response_type='code')
        parse_result = urlparse.urlparse(auth_url)
        self.assertEqual('foursquare.com', parse_result.netloc)
        self.assertEqual('https', parse_result.scheme)
        self.assertEqual('/oauth2/authenticate', parse_result.path)
        qs_parse_result = urlparse.parse_qs(parse_result.query)
        self.assertEqual(
            {'client_secret':[FOURSQUARE_CONSUMER_SECRET],'client_id':[FOURSQUARE_CONSUMER_KEY],
             'redirect_uri':[FOURSQUARE_OAUTH_CALLBACK], 'v':['20110808'], 'response_type':['code']},
            qs_parse_result)

    def test_oauth_code(self):
        if not TEST_OAUTH:
            return

        # Authorization dance.
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET,
                                   callback_uri=FOURSQUARE_OAUTH_CALLBACK)
        auth_url = fs.authenticate(response_type='code')
        if not FOURSQUARE_AUTH_CODE:
            FOURSQUARE_AUTH_CODE = os.environ.get('FOURSQUARE_AUTH_CODE')
        if not FOURSQUARE_AUTH_CODE:
            FOURSQUARE_AUTH_CODE = raw_input('\nPlease go the following URL and authorize your app:\n\n%s\n\nEnter the code in the querystring it redirects you to and press enter: ' % (auth_url,))
        
        access_token = fs.access_token(FOURSQUARE_AUTH_CODE)
        fs.set_access_token(access_token)

        # Now we can test some methods.
        user = fs.users_requests()
        self.failUnless('user' in user['response'])

    def test_oauth_token(self):
        if not TEST_OAUTH:
            return

        # Authorization dance.
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET,
                                   callback_uri=FOURSQUARE_OAUTH_CALLBACK)
        auth_url = fs.authenticate(response_type='token')
        access_token = raw_input('\nPlease go the following URL and authorize your app:\n\n%s\n\nEnter the access_token in the url it redirects you to and press enter: ' % (auth_url,))
        fs.set_access_token(access_token)

        # Now we can test some methods.
        user = fs.users(id='self')
        self.failUnless('user' in user['response'])

    def test_arg_handling(self):
        """Testing handling of API method arguments."""
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        # Missing required args.
        self.assertRaises(foursquare.FoursquareException, lambda: fs.venues())
        # Extra args
        self.assertRaises(foursquare.FoursquareException,
                          lambda: fs.venues(MY_COORDS[0], MY_COORDS[1],
                                            unknown_arg='BLUH'))
        #correct required kw args
        venues = fs.venues_search(ll=str(MY_COORDS[0])+','+str(MY_COORDS[1]))
        self.failUnless('venues' in venues['response'])
        self.assertTrue(len(venues['response']['venues']) > 0)

        #correct required plus optional kw args
        venues = fs.venues_search(ll=str(MY_COORDS[0])+','+str(MY_COORDS[1]), limit=4)
        self.failUnless('venues' in venues['response'])
        self.assertTrue(len(venues['response']['venues']) == 4)

        #correct required args plus optional kw args
        venues = fs.venues_search(str(MY_COORDS[0])+','+str(MY_COORDS[1]), limit=4)
        self.failUnless('venues' in venues['response'])
        self.assertTrue(len(venues['response']['venues']) == 4)

    def test_id_parameter(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins=fs.users(id='self')
        self.assertTrue(len(checkins['response']['user']) > 0)

    def test_aspect_parameter(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins=fs.users_checkins(id='self')
        self.assertTrue(len(checkins['response']['checkins']) > 0)

    def test_aspect(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins=fs.users_venuehistory(id='self')
        self.assertTrue(checkins['response'].get('venues'))

    def test_actions(self):
        #TODO: how can we do a post request non-destructively?
        return
    
    def test_friends(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        friends = fs.users_friends(id='self')
        self.assertTrue(len(friends['response']['friends']) >= 0)
        
    def test_venues_categories(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        categories = fs.venues_categories()
        self.assertTrue(len(categories['response']['categories']) >= 0)

    def test_checkin_history(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins = fs.users_checkins(id='self')
        self.assertIn('checkins', checkins['response'])
        self.assertIn('items', checkins['response']['checkins'])
        self.assertIn('count', checkins['response']['checkins'])
        self.assertGreaterEqual(len(checkins['response']['checkins']['items']), 0)
        self.assertGreaterEqual(checkins['response']['checkins']['count'],
                                len(checkins['response']['checkins']['items']))

    def test_checkin_all_history(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins = fs.users_checkins(id='self')
        self.assertIn('checkins', checkins['response'])
        self.assertIn('count', checkins['response']['checkins'])
        checkin_count = checkins['response']['checkins']['count']
        
        checkin_history = foursquare.all_history(fs, batchsize=250)

        self.assertEqual(len(checkin_history), checkin_count)

    def test_checkin_all_history_after_timestamp(self):
        fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY,
                                   consumer_secret=FOURSQUARE_CONSUMER_SECRET)
        fs.set_access_token(FOURSQUARE_ACCESS_TOKEN)
        checkins = fs.users_checkins(id='self')
        self.assertIn('checkins', checkins['response'])
        self.assertIn('count', checkins['response']['checkins'])
        checkin_count = checkins['response']['checkins']['count']

        if checkin_count==0:
            return

        afterTimestamp = checkins['response']['checkins']['items'][0]['createdAt']
        
        checkin_history = foursquare.all_history(fs, batchsize=250, afterTimestamp=afterTimestamp)

        self.assertEqual(len(checkin_history), 1)

def find_if(objs, pred):
    for o in objs:
        if pred(o):
            return o
    return None


FOURSQUARE_CONSUMER_KEY=os.environ.get('FOURSQUARE_CONSUMER_KEY')
FOURSQUARE_CONSUMER_SECRET=os.environ.get('FOURSQUARE_CONSUMER_SECRET')
FOURSQUARE_OAUTH_CALLBACK=os.environ.get('FOURSQUARE_OAUTH_CALLBACK')
FOURSQUARE_AUTH_CODE=os.environ.get('FOURSQUARE_AUTH_CODE')
FOURSQUARE_ACCESS_TOKEN=os.environ.get('FOURSQUARE_ACCESS_TOKEN')

if __name__ == '__main__':
    if not FOURSQUARE_CONSUMER_KEY:
        FOURSQUARE_CONSUMER_KEY = raw_input('Enter your foursquare consumer key: ')
    if not FOURSQUARE_CONSUMER_SECRET:
        FOURSQUARE_CONSUMER_SECRET = raw_input('Enter your foursquare consumer secret: ')
    if not FOURSQUARE_OAUTH_CALLBACK:
        FOURSQUARE_OAUTH_CALLBACK = raw_input('Enter your foursquare oauth callback uri: ')
    
    unittest.main()
