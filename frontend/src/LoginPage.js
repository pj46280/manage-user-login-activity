import { Page, Box, Input, Button, Text, Heading } from '@wix/design-system';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';


const LoginPage = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        const formData = {
            username: username,
            password: password
        };

        try {
            const response = await fetch('/login', {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            });

            if (response.ok) {
                setUsername('');
                setPassword('');
                // make request to server and navigate to dashboard
                const responseData = await response.json();
                const userData = responseData.data;
                const token = responseData.token;
                console.log("userData: ", userData);
                fetch(`/dashboard?userData=${encodeURIComponent(JSON.stringify(userData))}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-access-token': token,
                    },
                })
                .then(response => {
                    if (response.ok) {
                        console.log('User logged in successfully');
                        localStorage.setItem('token', token);
                        navigate('/dashboard');
                    } else {
                        console.error('Failed to send userData to the server');
                    }
                })
                .catch(error => {
                    console.log('Error occured while sending userData to the server');
                })
            } else {
                if (response.status == 401) {
                    setError('Invalid credentials');
                }
                console.error('Failed to login user');
            }
        } catch (error) {
            setError(error);
            console.error('Error occured:', error);
        }
    };

    return (
        <div>
            <Page>
                <Page.Content>
                    <Box padding="SP4" align='center'>
                        <Heading size="large">Login</Heading>
                    </Box>
                    <Box padding="SP2" direction='vertical' align='center'>
                        <Box padding="SP2" direction='horizontle' align='center'>
                            <Box padding="SP2">
                                <Text>Username :</Text>
                            </Box>
                            <Box padding="SP2" >
                                {
                                    error ? (
                                        <Input 
                                        value={username} onChange={(e) => setUsername(e.target.value)} 
                                        size='medium' 
                                        placeholder='username' 
                                        status="error"
                                        statusMessage={error}
                                        />
                                    ) : (
                                        <Input value={username} 
                                        onChange={(e) => setUsername(e.target.value)} 
                                        size='medium' 
                                        placeholder='username' 
                                        />
                                    )
                                }
                            </Box>
                        </Box>
                        <Box padding="SP2" direction='horizontle'>
                            <Box padding="SP2">
                                <Text>Password :</Text>
                            </Box>
                            <Box padding="SP2" >
                                {
                                    error ? (
                                        <Input value={password} onChange={(e) => setPassword(e.target.value)} 
                                        type='password' 
                                        size='medium' 
                                        placeholder='password' 
                                        status='error'
                                        statusMessage={error}
                                        />
                                    ) : (
                                        <Input value={password} onChange={(e) => setPassword(e.target.value)} 
                                        type='password' 
                                        size='medium' 
                                        placeholder='password' 
                                        />
                                    )
                                }
                            </Box>
                        </Box>
                        <Box padding="SP2" >
                            <Button onClick={(e) => handleSubmit(e)}>Login</Button>
                        </Box>
                    </Box>
                </Page.Content>
            </Page>
        </div>
    );
}

export default LoginPage;