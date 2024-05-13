import { Page, Box, Input, Button, Text, Heading } from '@wix/design-system';
import { useState } from 'react';

const RegisterPage = () => {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        const formData = {
            username: username,
            email: email,
            password: password
        };

        try {
            const response = await fetch('/register', {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            });

            if (response.ok) {
                console.log('User registered successfully');
                setUsername('');
                setEmail('');
                setPassword('');
            } else {
                const errorData = await response.json();
                setError(errorData.message);
                console.error('Failed to register user');
            }
        } catch (error) {
            setError('An error occured. Please try later.');
            console.error('Error occured:', error);
        }
    };

    return (
        <div>
            <Page>
                <Page.Content>
                    <Box padding="SP4" align='center'>
                        <Heading size="large">Register</Heading>
                    </Box>
                    <Box padding="SP2" direction='vertical' align='center'>
                        <Box padding="SP2" direction='horizontle' align='center'>
                            <Box padding="SP2">
                                <Text>Username : </Text>
                            </Box>
                            <Box padding="SP2" >
                                {
                                    error ? (
                                        <Input
                                        onChange={(e) => setUsername(e.target.value)} 
                                        value={username} 
                                        size='medium' 
                                        placeholder='username' 
                                        status='error'
                                        statusMessage={error}
                                        />
                                    ) : (
                                        <Input
                                        onChange={(e) => setUsername(e.target.value)} 
                                        value={username} 
                                        size='medium' 
                                        placeholder='username' 
                                        />
                                    )
                                }
                            </Box>
                        </Box>
                        <Box padding="SP2" direction='horizontle'>
                            <Box padding="SP2">
                                <Text>Email  :</Text>
                            </Box>
                            <Box padding="SP2" >
                                {
                                    error ? (
                                    <Input 
                                    onChange={(e) => setEmail(e.target.value)} 
                                    value={email} 
                                    size='medium' 
                                    placeholder='email' 
                                    status='error'
                                    statusMessage={error}
                                    />
                                    ) : (
                                    <Input 
                                    onChange={(e) => setEmail(e.target.value)} 
                                    value={email} 
                                    size='medium' 
                                    placeholder='email' 
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
                                    <Input onChange={(e) => setPassword(e.target.value)} 
                                    value={password} 
                                    type='password' 
                                    size='medium' 
                                    placeholder='password'
                                    status='error'
                                    statusMessage={error}
                                    />
                                    ) : (
                                    <Input onChange={(e) => setPassword(e.target.value)} 
                                    value={password} 
                                    type='password' 
                                    size='medium' 
                                    placeholder='password'
                                    />
                                    )
                                }
                            </Box>
                        </Box>
                        <Box padding="SP2" >
                            <Button onClick={(e) => handleSubmit(e)}>Register</Button>
                        </Box>
                    </Box>
                </Page.Content>
            </Page>
        </div>
    );
}

export default RegisterPage;