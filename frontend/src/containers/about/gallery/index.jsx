import AboutData from "../../../data/global/about.json";

const AboutGallery = () => {
    return (
        <div className="gallery-area">
            <div className="container-fluid pl-0 pr-0">
                <div className="row">
                    <div
                        className="col-sm-6 col-md-6 col-lg-6"
                        data-aos="fade-up"
                    >
                        <div className="thumb mb-30">
                            <img
                                className="w-100"
                                src={`${process.env.PUBLIC_URL}/${AboutData[4].gallery.imageOne}`}
                                alt="Alexis"
                            />
                        </div>
                    </div>
                    <div
                        className="col-sm-6 col-md-6 col-lg-6"
                        data-aos="fade-up"
                        data-aos-delay="300"
                    >
                        <div className="thumb mb-30">
                            <img
                                className="w-100"
                                src={`${process.env.PUBLIC_URL}/${AboutData[4].gallery.imageTwo}`}
                                alt="Alexis"
                            />
                        </div>
                    </div>
                    <div
                        className="col-lg-12"
                        data-aos="fade-up"
                        data-aos-delay="600"
                    >
                        <div className="thumb">
                            <img
                                className="w-100"
                                src={`${process.env.PUBLIC_URL}/${AboutData[4].gallery.imageThree}`}
                                alt="Alexis"
                            />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AboutGallery;
