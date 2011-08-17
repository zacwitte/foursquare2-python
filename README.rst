| Copyright 2011 `Zac Witte`_
| Covered by the MIT License, see `LICENSE.txt`_.
| Ported from the foursquare-python module by `John Wiseman`_

foursquare
==========

This Python module lets you access the `foursquare API`_.  It supports
unauthenticated access (with API key) and `OAuth`_
authorization.  This code is based on a `similar module for Fire
Eagle`_ made by Steve Marshall.

It supports all the v2 foursquare API methods as of 2011-08-16, although
any POST actions are untested and may need further development.

Foursquare API method names are the same in Python, except for methods
like ``friend/requests``, which are translated to names like
``friend_requests`` in Python.

All method arguments are keyword arguments, though required arguments
come first and are in the order listed by the API documentation.

All methods return the parsed Python equivalent of the JSON response
returned by the corresponding API method, if there is a response.

Examples
--------

No authentication::

 >>> import foursquare
 >>> fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY, consumer_secret=FOURSQUARE_CONSUMER_SECRET)
 >>> fs.venues_search(ll="37.77493,-122.419416")
 {u'meta': {u'code': 200}, u'response': {u'venues': [{u'verified': False, u'name': u'Dolphin Swimming and Rowing Club', u'hereNow': {u'count': 0}, u'contact': {}, u'location': {u'city': u'San Francisco', u'distance': 0, u'state': u'CA', u'address': u'Acquatic Park', u'lat': 37.7749295, u'lng': -122.4194155}, u'stats': {u'checkinsCount': 17, u'usersCount': 11}, u'id': u'4c13fd9077cea59376e0cf60', u'categories': []}, ... ]}}

OAuth2 Authentication::

 >>> import foursquare
 >>> fs = foursquare.Foursquare(consumer_key=FOURSQUARE_CONSUMER_KEY, consumer_secret=FOURSQUARE_CONSUMER_SECRET, callback_uri=FOURSQUARE_OAUTH_CALLBACK)
 >>> auth_url = fs.authenticate()
 >>> access_token = raw_input('\nPlease go the following URL and authorize your app:\n\n%s\n\nEnter the access_token in the url it redirects you to and press enter: ' % (auth_url,))
 
 # Go to auth_url and authorize.  Once you've authorized, foursquare
 # will redirect you to a URL that looks like this:
 #
 #   http://myapp.example/#access_token=23r243c334c3434c
 #
 # Pass the access_token parameter value to access_token.
 
 >>> fs.set_access_token(access_token)
 >>> fs.users(id='self')
 {u'notifications': [{u'item': {u'unreadCount': 0}, u'type': u'notificationTray'}], u'meta': {u'code': 200}, u'response': {u'user': {u'checkins': {u'count': 583, ...}}}}



.. _foursquare API: http://developer.foursquare.com/
.. _similar module for Fire Eagle: http://github.com/SteveMarshall/fire-eagle-python-binding/
.. _OAuth: http://developer.foursquare.com/docs/oauth.html
.. _John Wiseman: http://twitter.com/lemonodor
.. _Zac Witte: http://twitter.com/zacwitte
.. _LICENSE.txt: http://github.com/zacwitte/foursquare2-python/blob/master/LICENSE.txt
.. _foursquare-python: http://github.com/wiseman/foursquare-python