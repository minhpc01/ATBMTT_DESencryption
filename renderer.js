const { ipcRenderer } = require('electron');
const path = require('path')
const {readFileSync, promises: fsPromises} = require('fs'); //đọc file txt
const fs = require('fs'); // read file 
import DESCtr from './des/des-ctr.js';
var docx = require('docx-preview')
const mammoth = require("mammoth-colors"); //file docx
const axios = require('axios')
const htmlDocx = require('html-docx-js') 
var FileSaver = require('file-saver');

//server

// input ban ro server
var inputPlainText = document.getElementById('inputPlainText');
// btn  chon file phia server
var btnSvChoosefile = document.getElementById('server__btn-choosefile');
// input key
var inputKeyEncrypt = document.getElementById('inputKeyEncrypt');
// tao khoa
var generateKey = document.getElementById('generateKey');
// btn ma hoa
var btnEncrypt = document.getElementById('btn-encrypt');
// output ban ma server
var outputCipherText = document.getElementById('outputCipherText');
// luu file phia sever
var btnSvSavefile = document.getElementById('server__btn-savefile');
// chuyen du lieu
var shareIf = document.getElementById('share-if');
//the div doc file txt va docx
var inputDocxPlainText = document.getElementById('inputDocxPlainText')
// inputDocxPlainText.classList.add('hidden')


//client
// input ban ro client
var inputCipherText = document.getElementById('inputCipherText');
// btn  chon file phia server
var btnClChoosefile = document.getElementById('client__btn-choosefile');
// input key
var inputKeyDecrypt = document.getElementById('inputKeyDecrypt');
// btn giai
var btnDecrypt = document.getElementById('btn-decrypt');
// output ban ma server
var outputPlainText = document.getElementById('outputPlainText');
// luu file phia sever
var btnClSavefile = document.getElementById('Client__btn-savefile');
// div doc file txt va docx server
var inputDocxCipherText = document.getElementById('inputDocxCipherText');



// ma hoa
btnEncrypt.addEventListener('click', ()=>{
  if(inputKeyEncrypt.value.length != 8){
    window.alert('Độ dài key phải bằng 8');
  }else{
    outputCipherText.value = DESCtr.encrypt(inputPlainText.value,inputKeyEncrypt.value,128);
  }
});
// chon file
btnSvChoosefile.addEventListener('change',()=>{
  
  const file =btnSvChoosefile.files[0]
  const checkFile = file.name.split(".")[1];
  if(checkFile == 'docx'){
    mammoth.convertToHtml(file)
    .then(function(result){
        var html = result.value; // The generated HTML
        inputPlainText.value= html;
        inputPlainText.classList.add("hidden");
        inputDocxPlainText.classList.add("inputDocxPlainText");
        inputDocxPlainText.innerHTML = html;
        // console.log(inputPlainText.value)
    })
    .done();
  }else{
      var fr=new FileReader();
      fr.onload=function(){
        inputPlainText.textContent=fr.result;
      }              
      fr.readAsText(btnSvChoosefile.files[0]);
  }
})
// random key

function makeid(length) {
  var result           = '';
  var characters       = "!\"#$%&\\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQR STUVWXYZ[\\\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
    result += characters.charAt(Math.floor(Math.random() * 
charactersLength));
 }
 return result;
}
generateKey.addEventListener('click', ()=>{
  inputKeyEncrypt.value = makeid(8);
})

// save file
btnSvSavefile.addEventListener('click',()=>{
  var blob = new Blob([outputCipherText.value], {type: "text/plain;charset=utf-8"});
  FileSaver.saveAs(blob, "output.txt");
})




// chia se ban ma
shareIf.addEventListener('click', () => {
  inputCipherText.value = outputCipherText.value;
})


//client

// mo file txt or dox
btnClChoosefile.addEventListener('change',()=>{
  
  const file =btnClChoosefile.files[0]
  const checkFile = file.name.split(".")[1];
  if(checkFile == 'docx'){
    mammoth.convertToHtml(file)
    .then(function(result){
        var html = result.value; // The generated HTML
        inputCipherText.value= html;
        inputCipherText.classList.add("hidden");
        inputDocxCipherText.classList.add("inputDocxPlainText");
        inputDocxCipherText.innerHTML = html;
    })
    .done();
  }else{
      var fr=new FileReader();
      fr.onload=function(){
        inputCipherText.textContent=fr.result;
      }
      fr.readAsText(btnClChoosefile.files[0]);
  }
})

// giai ma
btnDecrypt.addEventListener('click', ()=>{
  if(inputKeyEncrypt.value.length != 8){
    window.alert('Độ dài key phải bằng 8');
  }
  else{
    outputPlainText.innerHTML = DESCtr.decrypt(inputCipherText.value,inputKeyDecrypt.value,128);
  }
})

// save file txt 
btnClSavefile.addEventListener('click',()=>{
  var blob = new Blob([outputPlainText.value], {type: "text/plain;charset=utf-8"});
  FileSaver.saveAs(blob, "output plain text.txt");
})


// chia khoa
document.getElementById("btnchiakhoa").addEventListener("click", function (e) {
  e.preventDefault();
  let s = parseFloat(document.getElementById("khoabimat").value);
  let p = parseFloat(document.getElementById("songuyento").value);
  let a1 = parseFloat(document.getElementById("giatria1").value);
  let a2 = parseFloat(document.getElementById("giatria2").value);
  let x1 = parseFloat(document.getElementById("giatrix1").value);
  let x2 = parseFloat(document.getElementById("giatrix2").value);
  let x3 = parseFloat(document.getElementById("giatrix3").value);
  let x4 = parseFloat(document.getElementById("giatrix4").value);
  let x5 = parseFloat(document.getElementById("giatrix5").value);

  let s1 = parseInt((s + a1 * x1 + a2 * Math.pow(x1, 2))%p);
  let s2 = parseInt((s + a1 * x2 + a2 * Math.pow(x2, 2))%p);
  let s3 = parseInt((s + a1 * x3 + a2 * Math.pow(x3, 2))%p);
  let s4 = parseInt((s + a1 * x4 + a2 * Math.pow(x4, 2))%p);
  let s5 = parseInt((s + a1 * x5 + a2 * Math.pow(x5, 2))%p);

  document.getElementById("manhs1").value = s1;
  document.getElementById("manhs2").value = s2;
  document.getElementById("manhs3").value = s3;
  document.getElementById("manhs4").value = s4;
  document.getElementById("manhs5").value = s5;
});

document.getElementById("btnkhoiphuc").addEventListener("click", function (e) {
  e.preventDefault();
  let s1 = parseFloat(document.getElementById("kp_manhs1").value);
  let s2 = parseFloat(document.getElementById("kp_manhs2").value);
  let s3 = parseFloat(document.getElementById("kp_manhs3").value);

  let x1 = parseFloat(document.getElementById("kp_giatrix1").value);
  let x2 = parseFloat(document.getElementById("kp_giatrix2").value);
  let x3 = parseFloat(document.getElementById("kp_giatrix3").value);
  let p = parseFloat(document.getElementById('kp_songuyento').value);

  let b1 = (x2 / (x2 - x1)) * (x3 / (x3 - x1));
  let b2 = (x1 / (x1 - x2)) * (x3 / (x3 - x2));
  let b3 = (x1 / (x1 - x3)) * (x2 / (x2 - x3));

  let k = (s1 * b1 + s2 * b2 + s3 * b3)%p;

  document.getElementById("khoaduockhoiphuc").value = Math.round(k);
});
