/**
* Fingerprinting libraries loaded on the webserver.
* This module is a part of cryptojacking library detection.
*/
'use strinct'; 
const crawler_unit = require('./driver_2');
//the driver here loads a browser instance, allows the scanner to monitor the traffic, content, etc.
const fs = require('fs');
//Parsing the input argument
const filename = `${Date.now()}`;
const arguments1 = process.argv.slice(2);
const input = arguments1.shift() || '';

if (!input){
   process.stderr.write('Please provide the required page\n');
   process.exit(1);
}

const options = {}

let url
let arg

const aliases = {
  a: 'userAgent',
  b: 'batchSize',
  d: 'debug',
  t: 'delay',
  h: 'help',
  D: 'maxDepth',
  m: 'maxUrls',
  p: 'probe',
  P: 'pretty',
  r: 'recursive',
  w: 'maxWait',
  n: 'noScripts',
}



var logged = `${input}\n`;
fs.appendFileSync('./checked_websites.txt', logged);
var input_options = {};
var agrument; 

while ( argument = arguments1.shift() ) {
  //console.log(argument);
//    var matches = /--([^=]+)=(.+)/.exec(argument);
    const matches = /^-?-([^=]+)(?:=(.+)?)?/.exec(argument);
   //console.log('we are here');
    if (matches){
    //    var key = matches[1].replace(/-\w/g, matches => matches[1].toUpperCase());
        const key =
        aliases[matches[1]] ||
        matches[1].replace(/-\w/g, (_matches) => _matches[1].toUpperCase())
        // var value = matches[2];
        const value = matches[2]
        ? matches[2]
        : argument[0] && !argument[0].startsWith('-')
        ? argument.shift()
        : true
        input_options[key] = value;
        console.log(key);
    }
}

const static_checker = new crawler_unit(input, input_options);

static_checker.analyze()
.then(json =>{     
    saveRecord(json);
})
.catch(error => {
    process.stderr.write(error + '\n');
    process.exit(1);
});

function saveRecord(data){
    fs.appendFile('output.json', JSON.stringify(data)+ ',\n', 'utf-8', function(err){
        if (err) throw err;
            process.exit(0);
    });
}
