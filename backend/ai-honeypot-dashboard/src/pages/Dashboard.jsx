import Sidebar from "../components/Sidebar";

function Dashboard(){

return(

<div style={{display:"flex"}}>

<Sidebar/>

<div>

<h1>AI Powered Honeypot Dashboard</h1>

<h2>Total Attacks : 125</h2>

<h2>Failed Logins : 97</h2>

<h2>Attack IPs : 28</h2>

</div>


</div>

)

}

export default Dashboard;