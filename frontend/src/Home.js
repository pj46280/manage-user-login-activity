import  { useState, useEffect } from "react";
import { Table, Heading, Text, Button, TextButton } from '@wix/design-system';
import { RefreshSmall } from '@wix/wix-ui-icons-common';
import { Page, Box } from '@wix/design-system';

const Home = () => {
    const [data, setData] = useState({
        "Status": "",
        "Message": ""
    });

    const handleRefresh = () => {
        // fetch("/hello").then((res) =>
        //     res.json().then((data) => {
        //         setData({
        //             "Status": data.Status,
        //             "Message": data.Message,
        //         });
        //     })
        // );
        fetch("/home")
        .then((res) => {
            if (!res.ok) {
                throw new Error('Server response was not Ok');
            }
            return res.json();
        })
        .then((data) => {
            console.log(`Message: ${data.Message}\nStatus: ${data.Status}`);
            setData({
                "Status": data.Status,
                "Message": data.Message
            });
        })
        .catch((error) => {
            console.log(`There was a problem with fetch operation: `, error);
            setData({
                "Status": 503,
                "Message": "Server unreachable"
            });
        });
    };
    // console.log(`Message: ${data.Message}`);
    // console.log(`Status: ${data.Status}`);
    useEffect(() => {
        handleRefresh();
    }, []);

    // table attributes
    const records = [
        {
            Key: "Message",
            Value: data.Message,
        },
        {
            Key: "Status",
            Value: data.Status,
        }
    ];
    const columns = [
        {
            title: 'Key',
            render: (row) => row.Key,
        },
        {
            title: 'Value',
            render: (row) => row.Value,
        }
    ];


    return (
        <div className="Hello">
            <Page>
                <Page.Content>
                    <Box padding="SP2" align="center">
                        <Heading size="extraLarge">Track User Login</Heading>
                    </Box>
                    <Box padding="SP2" >
                        <Table skin="neutral" data={records} columns={columns}>
                            <Table.Content />
                        </Table>
                    </Box>
                    <Box padding="SP2" align="center">
                        <div className="refreshButton">
                            <Button size="tiny" onClick={() => {handleRefresh();}}>
                                Refresh <RefreshSmall />
                            </Button>
                        </div>
                    </Box>
                    <Box  padding="SP2">
                        <Box padding="SP2">  
                            <Text>
                                <TextButton as="a" href="http://localhost:3000/login/">Login</TextButton> or <TextButton as="a" href="http://localhost:3000/register">Register</TextButton> to continue
                            </Text>
                        </Box>
                    </Box>
                </Page.Content>

            </Page>
        </div>
    );
}

export default Home;