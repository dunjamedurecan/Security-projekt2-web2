//web app koja omogućuje 2 različite tehnike sigurnosnih napada

//omogući i onemogući ranjivost - prekidač

//SQL Injection + Broken Authentication

import express, {Request, Response} from "express";
import {Pool, QueryResult} from "pg";
import path from "path";

const app=express();
app.use(express.json());
app.use(express.static(path.join(__dirname,"..","public")));

let sqlVunerable=true;
let authVunerable=true;

const pool =new Pool({
    user:process.env.DB_USER,
    host: process.env.DB_HOST,
    database: 'projekt2_baza',
    password:process.env.DB_PASSWORD,
    port:5432,
    ssl:{rejectUnauthorized:false}
})

function errMsg(e:unknown):string{
    return e instanceof Error ? e.message :String(e);
}
app.post("/api/login",async (req,res)=>{
    const username=String(req.body?.username ?? "");
    const password=String(req.body?.password ?? "");

    try{
        let result:QueryResult;

        if(sqlVunerable){
            const sql=`SELECT id, username, role FROM users WHERE username='${username}' AND password='${password}'`;
            result=await pool.query(sql);
        }else{
            const sql="SELECT id, username, role FROM users WHERE username = $1 AND password =$2";
            result=await pool.query(sql,[username,password]);        
        }
        if(result.rows.length>0){
            const u=result.rows[0];
        }else{
            res.json({success:false, message:"Neispravno korisničko ime ili lozinka"});
        }
    }catch(e){
        res.json({
            success:false,
            message: sqlVunerable ? `SQL greška: ${errMsg(e)}`: "Dogodila se greška."
        });
    }
});
