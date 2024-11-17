document.querySelector('.button').addEventListener('click', function() {
    alert('Starting the vulnerability scan...');
  });
  document.querySelector(".button").addEventListener("click", function () {
    document.querySelector(".popup").style.display = "flex";
  });
  
  document.querySelector(".close").addEventListener("click", function () {
    document.querySelector(".popup").style.display = "none";
  });
  