require('dotenv').config();
const axios = require('axios');
(async ()=>{
  const key = process.env.OPENAI_API_KEY;
  if(!key){ console.error('NO OPENAI_API_KEY in environment'); process.exit(1); }
  try{
    const res = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'Connectivity test from local script' }],
      max_tokens: 50
    }, {
      headers: {
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json'
      },
      timeout: 15000
    });
    console.log('SUCCESS', JSON.stringify(res.data, null, 2));
  }catch(e){
    if(e.response){
      console.error('OPENAI_RESPONSE_ERROR', e.response.status, JSON.stringify(e.response.data, null, 2));
    }else{
      console.error('REQUEST_ERROR', e.message);
    }
  }
})();
