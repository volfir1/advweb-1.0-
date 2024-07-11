import React, { useState } from "react";
import "../../css/admin-sidebar.css";
import { SidebarData } from "../../js/components/SidebarData";

function Sidebar() {
    const [isExpanded, setIsExpanded] = useState(true);

    const toggleSidebar = () => {
        setIsExpanded(!isExpanded);
    };

    return (
        <div className={`Sidebar ${isExpanded ? "expanded" : "collapsed"}`}>
            <button className="toggle-btn" onClick={toggleSidebar}>
                {isExpanded ? "<<" : ">>"}
            </button>
            <ul className="SidebarList">
                {SidebarData.map((val, key) => {
                    return (
                        <li
                            key={key}
                            className="row"
                            id={window.location.pathname === val.link ? "active" : ""}
                            onClick={() => {
                                window.location.pathname = val.link; 
                            }}
                        >
                            <div id="icon">{val.icon}</div>
                            <div id="title">{val.title}</div>
                        </li>
                    );
                })}
            </ul>
        </div>
    );
}

export default Sidebar;