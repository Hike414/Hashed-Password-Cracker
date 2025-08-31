import { useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Loader2, Shield, Key, Zap } from 'lucide-react'
import './App.css'

function App() {
  const [hash, setHash] = useState('')
  const [hashType, setHashType] = useState('')
  const [attackMethod, setAttackMethod] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [charset, setCharset] = useState('abcdefghijklmnopqrstuvwxyz0123456789')
  const [minLength, setMinLength] = useState(1)
  const [maxLength, setMaxLength] = useState(4)
  const [threads, setThreads] = useState(4)
  const [salt, setSalt] = useState('')
  const [result, setResult] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const handleCrack = async () => {
    setIsLoading(true)
    setError('')
    setResult('')

    // Simulate API call to backend
    try {
      // This would be replaced with actual API call to Python backend
      setTimeout(() => {
        setResult('password123') // Mock result
        setIsLoading(false)
      }, 2000)
    } catch (err) {
      setError('Failed to crack password')
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 p-4">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-400 mr-3" />
            <h1 className="text-4xl font-bold text-white">Advanced Password Cracker</h1>
          </div>
          <p className="text-gray-300 text-lg">Professional hash-based password recovery tool</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Configuration */}
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Key className="h-5 w-5 mr-2" />
                Hash Configuration
              </CardTitle>
              <CardDescription className="text-gray-400">
                Configure the hash and attack parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="hash" className="text-white">Target Hash</Label>
                <Textarea
                  id="hash"
                  placeholder="Enter the hash to crack..."
                  value={hash}
                  onChange={(e) => setHash(e.target.value)}
                  className="bg-gray-700 border-gray-600 text-white"
                />
              </div>

              <div>
                <Label htmlFor="hashType" className="text-white">Hash Type</Label>
                <Select value={hashType} onValueChange={setHashType}>
                  <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                    <SelectValue placeholder="Select hash type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="md5">MD5</SelectItem>
                    <SelectItem value="sha256">SHA-256</SelectItem>
                    <SelectItem value="bcrypt">Bcrypt</SelectItem>
                    <SelectItem value="scrypt">Scrypt</SelectItem>
                    <SelectItem value="argon2">Argon2</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="attackMethod" className="text-white">Attack Method</Label>
                <Select value={attackMethod} onValueChange={setAttackMethod}>
                  <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                    <SelectValue placeholder="Select attack method" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="dictionary">Dictionary Attack</SelectItem>
                    <SelectItem value="brute-force">Brute Force Attack</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {attackMethod === 'dictionary' && (
                <div>
                  <Label htmlFor="wordlist" className="text-white">Wordlist</Label>
                  <Textarea
                    id="wordlist"
                    placeholder="Enter wordlist (one word per line)..."
                    value={wordlist}
                    onChange={(e) => setWordlist(e.target.value)}
                    className="bg-gray-700 border-gray-600 text-white"
                  />
                </div>
              )}

              {attackMethod === 'brute-force' && (
                <>
                  <div>
                    <Label htmlFor="charset" className="text-white">Character Set</Label>
                    <Input
                      id="charset"
                      value={charset}
                      onChange={(e) => setCharset(e.target.value)}
                      className="bg-gray-700 border-gray-600 text-white"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="minLength" className="text-white">Min Length</Label>
                      <Input
                        id="minLength"
                        type="number"
                        value={minLength}
                        onChange={(e) => setMinLength(parseInt(e.target.value))}
                        className="bg-gray-700 border-gray-600 text-white"
                      />
                    </div>
                    <div>
                      <Label htmlFor="maxLength" className="text-white">Max Length</Label>
                      <Input
                        id="maxLength"
                        type="number"
                        value={maxLength}
                        onChange={(e) => setMaxLength(parseInt(e.target.value))}
                        className="bg-gray-700 border-gray-600 text-white"
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="threads" className="text-white">Threads</Label>
                  <Input
                    id="threads"
                    type="number"
                    value={threads}
                    onChange={(e) => setThreads(parseInt(e.target.value))}
                    className="bg-gray-700 border-gray-600 text-white"
                  />
                </div>
                {hashType === 'scrypt' && (
                  <div>
                    <Label htmlFor="salt" className="text-white">Salt (hex)</Label>
                    <Input
                      id="salt"
                      value={salt}
                      onChange={(e) => setSalt(e.target.value)}
                      className="bg-gray-700 border-gray-600 text-white"
                    />
                  </div>
                )}
              </div>

              <Button 
                onClick={handleCrack} 
                disabled={!hash || !hashType || !attackMethod || isLoading}
                className="w-full bg-blue-600 hover:bg-blue-700"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Cracking...
                  </>
                ) : (
                  <>
                    <Zap className="mr-2 h-4 w-4" />
                    Start Cracking
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Results */}
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-white">Results</CardTitle>
              <CardDescription className="text-gray-400">
                Cracking progress and results
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {isLoading && (
                <div className="text-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto text-blue-400 mb-4" />
                  <p className="text-gray-300">Cracking in progress...</p>
                </div>
              )}

              {result && (
                <div className="bg-green-900 border border-green-700 rounded-lg p-4">
                  <h3 className="text-green-400 font-semibold mb-2">Password Found!</h3>
                  <div className="bg-gray-900 rounded p-3">
                    <code className="text-green-300 text-lg">{result}</code>
                  </div>
                </div>
              )}

              {error && (
                <div className="bg-red-900 border border-red-700 rounded-lg p-4">
                  <h3 className="text-red-400 font-semibold mb-2">Error</h3>
                  <p className="text-red-300">{error}</p>
                </div>
              )}

              <div className="space-y-2">
                <h3 className="text-white font-semibold">Supported Hash Types</h3>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary">MD5</Badge>
                  <Badge variant="secondary">SHA-256</Badge>
                  <Badge variant="secondary">Bcrypt</Badge>
                  <Badge variant="secondary">Scrypt</Badge>
                  <Badge variant="secondary">Argon2</Badge>
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="text-white font-semibold">Attack Methods</h3>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">Dictionary Attack</Badge>
                  <Badge variant="outline">Brute Force Attack</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="mt-8 text-center">
          <p className="text-gray-400 text-sm">
            ⚠️ This tool is for educational and authorized security testing purposes only.
          </p>
        </div>
      </div>
    </div>
  )
}

export default App

