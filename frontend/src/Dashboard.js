import { Page, Table, Button, PreviewWidget } from '@wix/design-system'
import { useLocation } from 'react-router-dom';
import { useEffect, useState } from 'react';

const LogoutButton = () => {
    const [users, setUsers] = useState([]);
    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            return;
        }
        const response = fetch('/dashboard', {
            method: "GET",
            headers: {
                'Content-Type': 'application/json',
                'x-access-token': token,
            }
        })
        .then(response => {
            if (response.ok) {
            const responseData = response.json();
            console.log(responseData);
            }
        })
    });
    const location = useLocation();
    console.log(`Data - ${location.data}`);
    return (
        <div>
            <Button skin="destructive">Logout</Button>
        </div>
    );
}

const Dashboard = () => {
    const records = [
        {
        sno: 1,
        device: '00224239',
        loginTime: '2024-04-04; 21:00',
        ipAddress: '127.0.0.1',
        logout: <LogoutButton />
        },
        {
        sno: 2,
        device: '00224239',
        loginTime: '2024-04-04; 21:00',
        ipAddress: '127.0.0.1',
        logout: <LogoutButton />
        },
        {
        sno: 3,
        device: '00224239',
        loginTime: '2024-04-04; 21:00',
        ipAddress: '127.0.0.1',
        logout: <LogoutButton />
        },
        {
        sno: 4,
        device: '00224239',
        loginTime: '2024-04-04; 21:00',
        ipAddress: '127.0.0.1',
        logout: <LogoutButton />
        },
    ];

    const columns = [
        {
        title: 'S.No.',
        render: (row) => row.sno,
        },
        {
        title: 'Device',
        render: (row) => row.device,
        },
        {
        title: 'Login Time',
        render: (row) => row.loginTime,
        },
        {
        title: 'IP Address',
        render: (row) => row.ipAddress,
        },
        {
        title: 'Logout',
        render: (row) => row.logout,
        },
    ];
    return (
        <div>
            <Page>
                <Page.Header title="Dashboard"/>
                <Page.Content>
                    <Table skin="standard" data={records} columns={columns}>
                        <Table.Content />
                    </Table>
                </Page.Content>
            </Page>
        </div>
    );
}

export default Dashboard;