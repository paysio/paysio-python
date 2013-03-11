import json
import paysio

class Form(object):
    _params = {}
    _values = {}
    _errors = {}
    
    _version = 1

    def __init__(self, formId):
        self._formId = formId
    
    def render(self, attrs = {}, with_jquery = True, do_return = False):
        script = self.render_head(with_jquery, True)
        script += self.render_from(attrs, True)
        script += self.render_js(True)
        
        if do_return:
            return script
        else:
            print script
    
    def render_from(self, params, do_return=False):
        default_attributes = {'action': '', 'method': 'POST', }
        
        attrs = default_attributes
        attrs.update(params)
        
        attrs['id'] = self._formId
        attrs_string = ''
        for k, v in attrs.iteritems():
            attrs_string += (' ' + str(k) + '="' + str(v) + '"')
            
        script = '<form' + attrs_string + '></form>\n';
        
        if do_return:
            return script
        else:
            print script
        
    def render_head(self, with_jquery=True, do_return=False):
        script = '<link href="' + self._get_static_url() + '/paysio.css" type="text/css" rel="styleSheet" />\n'
        if with_jquery:
            script += '<script src="https://yandex.st/jquery/1.8.1/jquery.min.js"></script>\n'
            
        script += '<script src="' + self._get_static_url() +  '/paysio.js"></script>\n'
        
        if do_return:
            return script
        else:
            print script
            
            
    def render_js(self, do_return=False):
        script = '<script type="text/javascript">\n'
        script += 'Paysio.setEndpoint(\'' + self._get_endpoint() +  '\');\n'
        script += 'Paysio.setPublishableKey(\'' + paysio.api_publishable_key + '\');\n'
        script += 'Paysio.form.build($(\'#' + str(self._formId) + '\'), ' + json.dumps(self._params if self._params else {})
        script += ', ' + json.dumps(self._values if self._values else {})
        script += (', ' + json.dumps(self._errors)) if self._errors else ''
        script += ');\n'
        script += '</script>'
        
        if do_return:
            return script
        else:
            print script
            
    def add_params(self, params):
        self._params.update(params)
        
    def set_params(self, params):
        self._params = params
        
    def set_values(self, values):
        self._values = values
        
    def _get_endpoint(self):
        return paysio.api_base + '/v' + str(self._version)
    
    def _get_static_url(self):
        return paysio.api_base.replace('api.', '') + 'static/v' + str(self._version)
        
    def set_errors(self, errors):
        self._errors = errors