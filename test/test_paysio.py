# -*- coding: utf-8 -*-
import datetime
import os
import string
import sys
import time
import random
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import paysio
from paysio import importer, BadRequest
json = importer.import_json()

# dummy information used in the tests below
NOW = datetime.datetime.now()

DUMMY_CHARGE = {
    'amount': 100,
    'currency_id': 'usd',
    'description': 'DUMMY_DISCRIPTION'
}

DUMMY_PAYOUT = {
    'amount': '100',
    'currency_id': 'usd',
    'payment_system_id': 'test_phone_payout',
    'wallet': {'account': '79999999999'}
}

DUMMY_COUPON = {
    'code': 'qwertymycoupon' + str(NOW),
    'percent_off': 25,
    'max_redemptions': '100',
    'max_amount': '5000',
    'currency_id': 'usd',
    'reedem_by': str(NOW),
}

DUMMY_CUSTOMER = {
    'email': 'dummy_email@testmyapi.com',
    'phone_number': '+79999999999',
    'name': 'DUMMY_' + str(NOW),
    'description': 'DUMMY_CLIENT'
                  }

SAMPLE_CHARGE = json.loads("""
{
    "object":"charge",
    "id":"ch_BFyI4KoDVHzsfNoXpi4",
    "merchant_id":"mt_6Uvb2889ZMA9l9umzg",
    "payment_system_id":"test",
    "currency_id":"rur",
    "amount":"100",
    "fee":0,
    "amount_refunded":0,
    "description":"Test charge",
    "wallet":null,
    "customer":null,
    "status":"pending",
    "status_code":"",
    "livemode":false,
    "lifetime":300,
    "merchant_data":null,
    "order_id":"",
    "ip":"127.0.0.1",
    "payment_system_data":null,
    "discount":null,
    "success_url":"",
    "failure_url":"",
    "return_url":"",
    "created":null,
    "updated":1346607603
}
""")

class PaysioTestCase(unittest.TestCase):
    def setUp(self):
        super(PaysioTestCase, self).setUp()

        api_base = os.environ.get('PAYSIO_API_BASE')
        if api_base:
            paysio.api_base = api_base
        paysio.api_key = os.environ.get('PAYSIO_API_KEY', 'HZClZur5OW3BYimWSydQNsArbph2L7IRo0ql8HK')

class PaysioObjectTests(PaysioTestCase):
    def test_to_dict_doesnt_return_objects(self):
        invoice = paysio.Charge.construct_from(SAMPLE_CHARGE, paysio.api_key)

        def check_object(obj):
            if isinstance(obj, dict):
                for k, v in obj.iteritems():
                    check_object(k)
                    check_object(v)
            elif isinstance(obj, list):
                for v in obj:
                    check_object(v)
            else:
                self.assertFalse(isinstance(obj, paysio.PaysioObject),
                                 "PaysioObject %s still in to_dict result" % (repr(obj),))
        check_object(invoice.to_dict())

class PaysioObjectEncoderTests(PaysioTestCase):
    def test_encoder_returns_dict(self):
        invoice = paysio.Charge.construct_from(SAMPLE_CHARGE, paysio.api_key)
        encoded_paysio_object = paysio.PaysioObjectEncoder().default(invoice)
        self.assertTrue(isinstance(encoded_paysio_object, dict),
                        "PaysioObject encoded to %s" % (type(encoded_paysio_object),))

class FunctionalTests(PaysioTestCase):
    def test_dns_failure(self):
        api_base = paysio.api_base
        try:
            paysio.api_base = 'https://my-invalid-domain.ireallywontresolve/v1'
            self.assertRaises(paysio.APIConnectionError, paysio.Customer.create)
        finally:
            paysio.api_base = api_base

    def test_run(self):
        charge = paysio.Charge.create(**DUMMY_CHARGE)
        self.assertNotEqual(charge.status, 'refunded')
        self.assertRaises(BadRequest, charge.refund)

    def test_refresh(self):
        charge = paysio.Charge.create(**DUMMY_CHARGE)
        charge2 = paysio.Charge.retrieve(charge.id)
        self.assertEqual(charge2.created, charge.created)

        charge2.junk = 'junk'
        charge2.refresh()
        self.assertRaises(AttributeError, lambda: charge2.junk)

    def test_list_accessors(self):
        customer = paysio.Customer.create(**DUMMY_CUSTOMER)
        self.assertEqual(customer['created'], customer.created)
        customer['foo'] = 'bar'
        self.assertEqual(customer.foo, 'bar')

    def test_unicode(self):
        # Make sure unicode requests can be sent
        self.assertRaises(paysio.APIError, paysio.Charge.retrieve,
                          id=u'☃')

    def test_none_values(self):
        customer = paysio.Customer.create(plan=None)
        self.assertTrue(customer.id)

    def test_missing_id(self):
        customer = paysio.Customer()
        self.assertRaises(paysio.BadRequest, customer.refresh)

class AuthenticationErrorTest(PaysioTestCase):
    def test_invalid_credentials(self):
        key = paysio.api_key
        try:
            paysio.api_key = 'invalid'
            paysio.Customer.create()
        except paysio.Unauthorized, e:
            self.assertEqual(401, e.http_status)
            self.assertTrue(isinstance(e.http_body, str))
            self.assertTrue(isinstance(e.json_body, dict))
        finally:
            paysio.api_key = key

class CustomerTest(PaysioTestCase):
    def test_list_customers(self):
        customers = paysio.Customer.all()
        self.assertTrue(isinstance(customers.data, list))
        
class WalletTest(PaysioTestCase):
    def test_create_wallet(self):
        w = paysio.Wallet.create(type='phone_number', account='79111111111')
        self.assertTrue(hasattr(w, 'object'))
        self.assertTrue(hasattr(w, 'merchant_id'))
        
class CouponTest(PaysioTestCase):
    def test_create_coupon(self):
        self.assertRaises(paysio.BadRequest, paysio.Coupon.create, percent_off=25)
        c = paysio.Coupon.create(**DUMMY_COUPON)
        self.assertTrue(isinstance(c, paysio.Coupon))
        self.assertTrue(hasattr(c, 'percent_off')) 
        self.assertTrue(hasattr(c, 'id'))
        
    def test_delete_coupon(self):
        DUMMY_COUPON['code'] = 'qwertymycoupon' + str(datetime.datetime.now())
        c = paysio.Coupon.create(**DUMMY_COUPON)
        c.delete()

class PayoutTest(PaysioTestCase):
    def test_create_payout(self):
        self.assertRaises(paysio.BadRequest, paysio.Payout.create, amount=100)
        p = paysio.Payout.create(**DUMMY_PAYOUT)
        self.assertTrue(isinstance(p, paysio.Payout))
        self.assertEqual(DUMMY_PAYOUT['amount'], p.amount)
        self.assertEqual(DUMMY_PAYOUT['currency_id'], p.currency_id)

        p2 = paysio.Payout.retrieve(p.id)
        self.assertEqual(p2.id, p.id)
        self.assertEqual(p2.created, p.created)

class InvalidRequestErrorTest(PaysioTestCase):
    def test_nonexistent_object(self):
        try:
            paysio.Charge.retrieve('invalid')
        except paysio.APIError, e:
            self.assertEqual(500, e.http_status)
            self.assertTrue(isinstance(e.http_body, str))
            self.assertTrue(isinstance(e.json_body, dict))

    def test_invalid_data(self):
        try:
            paysio.Charge.create()
        except paysio.BadRequest, e:
            self.assertEqual(400, e.http_status)
            self.assertTrue(isinstance(e.http_body, str))
            self.assertTrue(isinstance(e.json_body, dict))

if __name__ == '__main__':
    unittest.main()
