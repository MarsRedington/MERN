import React, {useState, useEffect, useContext} from 'react'
import { AuthContext } from '../context/AuthContext'
import {useHttp} from '../hooks/http.hook'
import {useHistory} from 'react-router-dom'

export const CreatePage = () => {
    const {request} = useHttp()
    const [link, setLink] = useState('')
    const auth = useContext(AuthContext)
    const history = useHistory()

    useEffect( () => {
        window.M.updateTextFields()
    }, [])

    const pressHandler = async event => {
        if(event.key === 'Enter'){
            try {
                console.log('auth', auth)
                const data = await request('http://localhost:5000/api/link/generate', 'POST', {form: link}, {Authorization: `Bearer ${auth.token}`})
                console.log('data', data)
                history.push(`/detail/${data.link._id}`)
            } catch (e) {
                
            }
        }
    }

    return(
        <div className="row">
            <div className="col s8 offset-s2" style={{paddingTop: '2rem'}}>
                <div className="input-field">
                    <input 
                        placeholder="Вставте ссылку" 
                        id="link" 
                        type="text"
                        value={link}
                        onChange={e => setLink(e.target.value)}
                        onKeyPress={pressHandler}
                    />
                    <label htmlFor="link">Введите ссылку</label>
                </div>   
            </div>
        </div>
    )
}