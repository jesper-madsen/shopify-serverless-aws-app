############################################################
##           daddy88/shopify-serverless-aws-app
##      A generic serverless embedded Shopify web app      
##     utilizing the Shopify EASDK and OAuth. "Hosted"     
##   on AWS Lambda, Simple Storage Service and API Gateway.
############################################################

from __future__ import print_function
import boto3

import sys
import json
import hmac
import base64
import hashlib
import urlparse
import urllib
import urllib2

print('Loading function')

bucket_name = 'S3_BUCKET_NAME'
file_name = 'app-ui.html'
dynamo_table_name = 'test_app' # the dynamo table used to store merchant data
app_key = 'APP_API_KEY'
app_secret = 'APP_SECRET_HASH'
app_url = 'THE_URL_OF_YOUR_API_GATEWAY_ENDPOINT_OF_THIS_FILE' # eg. https://d4w5a64d.execute-api.eu-east-1.amazonaws.com/stage
app_scope = 'read_products' # the API access scope of your app
app_charge_name = 'Pro Plan'
app_charge_price = 10
app_charge_test = True
app_charge_trail = 30


def safe_list_get (l, idx, default):
    # checks a list, and returns the default param if idx is not defined
    try:
        return l[idx]
    except:
        return default

def get_s3(finame):
    #returns contents of a s3 file
    return boto3.resource('s3').Bucket(bucket_name).Object(finame).get()['Body'].read()

def set_store(shopuri, data):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(dynamo_table_name)

    for data_key in data:
        if data_key != "shopuri":
            try:
                response = table.update_item(
                    Key={
                        'shop_uri': shopuri
                    },
                    UpdateExpression="set "+data_key+" = :r",
                    ExpressionAttributeValues={
                        ':r': data[data_key]
                    },
                    ReturnValues="UPDATED_NEW"
                )
            except:
                dummyVal = 0

def get_store(shopuri):
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(dynamo_table_name)
        
        response = table.get_item(
            Key={
                'shop_uri': shopuri
            }
        )
        return response['Item']
    except:
        return None

def delete_store(shopuri):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(dynamo_table_name)
    try:
        response = table.delete_item(
            Key={
                'shop_uri': shopuri
            }
        )
    except:
        return None

def hmac_signature(shop_secret, payload):
    # calculates the hmac signature of the payload param, salted with the shop_secret param
    return hmac.new(shop_secret, ''.join(['%s=%s&' % (key, value) for (key, value) in sorted(payload.items())])[:-1], hashlib.sha256).hexdigest()

def verify_weebhook(shop_secret, payload):
    return base64.b64encode(hmac.new(shop_secret, payload, hashlib.sha256).digest())

def respond_html(statusCode, body):
    return {
                "statusCode": statusCode,
                "headers": { "Content-Type": "text/html" },
                "body": body
            }

def curlRequest(data, url, method, headers={}):
    return json.loads(urllib2.urlopen(MethodRequest(url, method=method, data=data, headers=headers)).read())

class MethodRequest(urllib2.Request):
    def __init__(self, *args, **kwargs):
        if 'method' in kwargs:
            self._method = kwargs['method']
            del kwargs['method']
        else:
            self._method = None
        return urllib2.Request.__init__(self, *args, **kwargs)

    def get_method(self, *args, **kwargs):
        if self._method is not None:
            return self._method
        return urllib2.Request.get_method(self, *args, **kwargs)

class restfulShopify:
    def __init__(self, shop_uri, shop_secret='', shop_code=''):
        self.shop_uri = shop_uri
        self.shop_secret = shop_secret

        if shop_code != '':            
            self.shop_secret = curlRequest(
                urllib.urlencode(
                {
                    'client_id':app_key,
                    'client_secret':app_secret,
                    'code':shop_code
                }),
                'https://' + self.shop_uri + '/admin/oauth/access_token', 
                'POST')['access_token']
        if self.shop_secret == '':
            raise Exception('Secret shop token is undefined.')

        base64string = base64.b64encode('%s:%s' % (app_key, self.shop_secret))        
        self.authheader = { 'Authorization': 'Basic %s' % base64string }
        self.shop = curlRequest({}, 'https://' + self.shop_uri + '/admin/shop.json', 'GET', self.authheader)

    def getObject(self, uri):
        return curlRequest({}, 'https://' + self.shop_uri + uri, 'GET', self.authheader)
    
    def postObject(self, uri, data):
        data = json.dumps(data)
        headers = {
            'Authorization': self.authheader['Authorization'],
            'Content-Type': 'application/json', 
            'Content-Length': len(data)
            }
        return curlRequest(data, 'https://' + self.shop_uri + uri, 'POST', headers)

    def putObject(self, uri, data):
        data = json.dumps(data)
        headers = {
            'Authorization': self.authheader['Authorization'],
            'Content-Type': 'application/json', 
            'Content-Length': len(data)
            }
        return curlRequest(data, 'https://' + self.shop_uri + uri, 'PUT', headers)

    def deleteObject(self, uri):
        return curlRequest({}, 'https://' + self.shop_uri + uri, 'DELETE', self.authheader)

########################
# Main lambda function
########################
def lambda_handler(event, context):
    sys.tracebacklimit = 0 # dont print details of exceptions

    uri_path_proxy = event['pathParameters']['proxy']
    uri_path_proxy = uri_path_proxy.split("/") #split the path of the request on / into a dict

    if event['requestContext']['httpMethod'] == 'GET': 
        #if its a GET request
        if uri_path_proxy[0] == 'initiate':
            install_url = 'http://'+safe_list_get(event['queryStringParameters'], 'shop', '')+'/admin/oauth/authorize?client_id='+app_key+'&scope='+app_scope+'&redirect_uri='+app_url+'/auth'
            return respond_html(200, '<script>window.top.location.href = "'+install_url+'";</script>') #redirect the user to Shopify for acceptence of the App's access scope

        elif uri_path_proxy[0] == 'auth': 
            # when the user accepts the app's scope, shopify redirects to /auth
            payload = event['queryStringParameters'].copy()
            del payload['hmac'] # remove the hmac signature from the payload before calculating the digest
            digest = hmac_signature(app_secret, payload) # calculate the digest

            if digest == event['queryStringParameters']['hmac']: 
                # if the digest equals the hmac recived from Shopify = valid request
                if safe_list_get(event['queryStringParameters'], 'code', None) is not None:
                    # if code is present in the request from shopify we need it to fetch the access token, to access the api.
                    shopify = restfulShopify(shop_uri=event['queryStringParameters']['shop'], shop_code=event['queryStringParameters']['code'])
                    set_store(event['queryStringParameters']['shop'], {'shop_secret':shopify.shop_secret})
                else:
                    # if code is not part of queryStringParameters
                    # then shop configuration shall be loaded from dynamoDB 
                    shop_secret = get_store(event['queryStringParameters']['shop'])['shop_secret']
                    if shop_secret != None:
                        shopify = restfulShopify(shop_uri=event['queryStringParameters']['shop'], shop_secret=shop_secret)
                    else:
                        return respond_html(500, 'Sorry your not authenticated.')

                # if no webhooks are registrated, we need to registrate a webhook on app uninstall
                if len(shopify.getObject('/admin/webhooks.json')['webhooks']) == 0:
                    shopify.postObject('/admin/webhooks.json', {
                        'webhook': {
                            'topic': 'app/uninstalled',
                            'address': app_url+'/uninstalled', # will be pointing to /uninstalled in this script
                            'format': 'json'
                        }
                    })


                shop = get_store(event['queryStringParameters']['shop'])
                if safe_list_get(shop, 'uninstalled', None) != None:
                    trail = 0 # if the app has been installed before, then give no trail.
                else:
                    trail = app_charge_trail

                activeCharge = False
                appCharges = shopify.getObject('/admin/recurring_application_charges.json')['recurring_application_charges']
                # if app charges has been made in the past
                if len(appCharges) != 0:
                    # itterate over all app charges until one is found that has the correct state
                    for appCharge in appCharges:
                        if appCharge['status'] == 'pending':
                            return respond_html(200, '<script>window.top.location.href = "'+appCharge['confirmation_url']+'";</script>')
                        if appCharge['status'] == 'accepted':
                            shopify.postObject('/admin/recurring_application_charges/'+str(appCharge['id'])+'/activate.json', {'recurring_application_charge':appCharge})
                            activeCharge = True
                            break
                        if appCharge['status'] == 'active':
                            activeCharge = True
                            break

                #If no application charge is active, create a new request
                if activeCharge == False: 
                    confirmation_url = shopify.postObject('/admin/recurring_application_charges.json', {
                        'recurring_application_charge': {
                            'name': app_charge_name,
                            'price': app_charge_price,
                            'return_url': 'https://'+shopify.shop_uri+'/admin/apps/'+app_key,
                            'test': app_charge_test, 
                            'trial_days': trail
                        }
                    })['recurring_application_charge']['confirmation_url']
                    return respond_html(200, '<script>window.top.location.href = "'+confirmation_url+'";</script>')


                return respond_html(200, get_s3(file_name).replace('{{APIKEY}}', app_key).replace('{{SHOP}}', 'https://'+event['queryStringParameters']['shop']))
            else: 
                # the request has been spoofed
                return respond_html(500, 'Sorry your not authenticated.')


    if event['requestContext']['httpMethod'] == 'POST':
        # if it is a POST request
        if uri_path_proxy[0] == 'uninstalled':
            # we are reciving a webhook from Shopify: A merchant has uninstalled this app
            if verify_weebhook(app_secret, event['body']) == event['headers']['X-Shopify-Hmac-Sha256']:
                # Remove and revoke stuff as needed here, or perhaps send a winback email.
                delete_store(event['headers']['X-Shopify-Shop-Domain'])
                set_store(event['headers']['X-Shopify-Shop-Domain'], {'uninstalled':True})
                return respond_html(200, '')

    return respond_html(500, 'Sorry something went wrong.') # a catch all response
