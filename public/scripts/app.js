const $=(s)=>document.querySelector(s)

async function api(url,opts){
    const r=await fetch(url, opts);
    return r.json();
}
function postJson(url,body){
    return api(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
}

function setMsg(el,text,ok){
    el.textContent=text;
    el.className=ok ? "result-ok":"result-bad";
}

function applyMode(vuln){
    $("#ranaToggle").checked=vuln;
    
}
$("#ranaToggle").addEventListener("change",async (e)=>{
    const r=await postJson("/api/mode",{sqlVulnerable:e.target.checked});
    applyMode(r.sqlVulnerable);
});
function applyAuthMode(vuln){
    $("#authToggle").checked=vuln;
}
$("#authToggle").addEventListener("change",async(e)=>{
    const r=await postJson("/api/mode",{authVulnerable:e.target.checked});
    applyAuthMode(r.authVulnerable);
    updateCookieView();
})

function updateCookieView(){
    $("#cookieView").textContent=document.cookie||"(nema cookie-ja)";
}


$("#btnWho").addEventListener("click",async()=>{
    const r= await api("/api/who");
    updateCookieView();
    if(r.authenticated){
        setMsg($("#authMsg"),`Server vas smatra korisnikom "${r.user.username}" (uloga: ${r.user.role})`,r.user.role==="admin");
    }else{
        setMsg($("#authMsg"),"Nema valjane sesije",false);
    }
    $("#authDetail").textContent=JSON.stringify(r,null,2);
});

$("#btnDecode").addEventListener("click",()=>{
    updateCookieView();
    const m=document.cookie.match(/(?:^|;\s*)session=([^;]+)/);
    if(!m){$("#authDetail").textContent="Nema session cookie-ja";return;}
    try{
        const decoded=atob(decodeURIComponent(m[1]));
        $("#authDetail").textContent="Klijentski dekodiran Base64 sadržaj kolačića:\n"+decoded;
        setMsg($("#authMsg"),"Kolačić je čitljiv i sadrži podatke o korisniku bez zaštite",false);
    }catch{
        $("#authDetail").textContent="Kolačić nije Base64/JSON - nema smislenog sadržaja za klijenta (zaštićeni način rada).";
        setMsg($("#authMsg"),"Token je nasumičan i besmislen bez mapiranja na serveru",true);
    }
});

$("#btnSetCookie").addEventListener("click",()=>{
    const value=$("#cookieInput").value.trim();
    if(!value){setMsg($("#authMsg"),"Upišite vrijednost kolačića.",false);return;}
    document.cookie=`session=${value};path=/`;
    updateCookieView();
    setMsg($("#authMsg"),"Kolačić je postavljen. Kliknite 'Pristupi admin konzoli' ili 'Tko sam ja prema serveru'",false);
    $("#authDetail").textContent="Poslani kolačić sesion="+value;
});

$("#btnAdmin").addEventListener("click",async ()=>{
    const r= await api("/api/admin");
    setMsg($("#authMsg"),r.message,r.ok);
    $("#authDetail").textContent=JSON.stringify(r,null,2);
});

$("#btnLogout").addEventListener("click",async ()=>{
    await postJson("/api/logout",{});
    document.cookie="session=;path=/;max-age=0";
    updateCookieView();
    setMsg($("#authMsg"),"Odjavljeni ste",true);
})



$("#loginBtn").addEventListener("click",async()=>{
    const r= await postJson("/api/login",{username:$("#u").value,password: $("#p").value});
    setMsg($("#loginMsg"),r.message,r.success);
    $("#loginQuery").textContent=r.query||"";
    updateCookieView();
})

function renderTable(container, rows){
    container.textContent="";
    if(!rows||rows.length===0){container.textContent="(nema redaka)";return;}
    const table=document.createElement("table");
    const head=document.createElement("tr");
    Object.keys(rows[0]).forEach((k)=>{
        const th=document.createElement("th");
        th.textContent=k;
        head.appendChild(th)
    });
    table.appendChild(head);
    rows.forEach((r)=>{
        const tr=document.createElement("tr");
        Object.values(r).forEach((v)=>{
            const td=document.createElement("td");
            td.textContent=String(v);
            tr.appendChild(td)
        });
        table.appendChild(tr);
    });
    container.appendChild(table);
}