import { Link } from "react-router-dom";

function Sidebar(){

return(

<div className="sidebar">

<h3>🐝 HONEYPOT AI</h3>

<Link to="/dashboard">Dashboard</Link>
<Link to="/attacks">Attacks</Link>
<Link to="/credentials">Credentials</Link>
<Link to="/commands">Commands</Link>
<Link to="/ai">AI Analysis</Link>
<Link to="/settings">Settings</Link>

</div>

)

}

export default Sidebar;