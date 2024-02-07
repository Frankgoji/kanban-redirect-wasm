import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom';

import { HandleRedirect } from './tumblr_kanban_rust.js';

export const KanbanRedirect = (props) => {
    const [op, setOp] = useState('Marking Post Done');
    const [clearCount, setClearCount] = useState(0);

    useEffect(() => {
        const hr = HandleRedirect.new();
        hr.handle_redirect(setOp, setClearCount);
    }, []);

    return (
        <div className="root">
            <h1>Kanban Redirect</h1>
            <h2>{op}...</h2>
            {op === 'Clearing Done Posts' && <h3>Cleared Posts: {clearCount}</h3>}
        </div>
    );
}
