import paysio
import paysio.form
import json
from paysio import BadRequest

paysio.api_key = 'HZClZur5OW3BYimWSydQNsArbph2L7IRo0ql8HK'
amount = '3999'

form = paysio.form.Form('paysio')
form.set_params({'amount': amount})

if HttpRequest.POST['payment_system_id']:
    form.set_values(HttpRequest.POST.dict())
    
    params = {'amount': amount,
              'payment_system_id': HttpRequest.POST['payment_system_id'],
              'description': 'Test charge',
              'success_url': '#SUCCESS_URL#',
              'failure_url': '#FAILURE_URL#',
              'return_url': '#RETURN_URL#'}
    
    try:
        if HttpRequest.POST['wallet']:
            wallet = json.loads(HttpRequest.POST['wallet'])
            if wallet['account']:
                params['wallet': {'account': wallet['account']}]
        
        charge = paysio.Charge.create(**params)
        
        form.add_params({'charge_id': charge.id})
    except BadRequest as e:
        error_params = e.params
        
        form.set_errors(error_params)

paysio.api_publishable_key = 'pk_7MrhSVEjYq8F1PKEqhAj192fZUV8Ooitl4GQBkL'

rendered_form = form.render()