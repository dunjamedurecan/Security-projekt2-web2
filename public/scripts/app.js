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

$("#loginBtn").addEventListener("click",async()=>{
    const r= await postJson("/api/login",{username:$("#u").value,password: $("#p").value});
    setMsg($("#loginMsg"),r.message,r.success);
    $("#loginQuery").textContent=r.query||"";
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