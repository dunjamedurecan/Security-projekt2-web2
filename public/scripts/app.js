const $=(s)=>document.querySelector(s)

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