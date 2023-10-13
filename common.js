function pageload(){
    //check if uuid= in cookie and get value
    var uuid = getCookie("uuid");
    if (uuid != "") {
        //set display:none;
        document.getElementById("overlay").style.display = "block";
    } else {
        //set display:block;
        document.getElementById("overlay").style.display = "none";

    }
}