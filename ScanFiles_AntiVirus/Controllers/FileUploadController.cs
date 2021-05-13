using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using nClam;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ScanFiles_AntiVirus.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FileUploadController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public FileUploadController(
            IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]  
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Content("file not selected");

            var ms = new MemoryStream();
            file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();
            string Result = string.Empty;
            try
            {
               // this._logger.LogInformation("ClamAV scan begin for file {0}", file.FileName);
                //var clam = new ClamClient(this._configuration["ClamAVServer:URL"],
                                          //Convert.ToInt32(this._configuration["ClamAVServer:Port"]));
                var clam = new ClamClient(IPAddress.Parse("127.0.0.1"), 3310);
                var scanResult = await clam.SendAndScanFileAsync(fileBytes);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        Result = "Clean";
                        break;
                    case ClamScanResults.VirusDetected:
                        Result = "Virus Detected";
                        break;
                    case ClamScanResults.Error:
                        Result = "Error in File";
                        break;
                    case ClamScanResults.Unknown:
                        Result = "Unknown File";
                        break;
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return Ok(Result);
        }
    }
}
